//! Ipe.Http.Server runtime — axum/hyper under a Ipê-native surface.
//!
//! Handlers are Ipê closures `Fn(Request) -> Task Error Response`. server_get
//! ERASES the project-defined error type E into a non-generic ServerRoute
//! (awaiting the task, mapping Err -> 500) so routes are uniform yet handlers
//! stay Send+Sync+'static for axum. server_listen builds an axum Router and
//! serves via tokio.
//!
//! `Request` and `Response` are OPAQUE `Ty::Con` types in the compiler IR
//! (`ipe_ir::IrType::ServerRequest` / `ServerResponse`). Ipê code cannot
//! construct or mutate them directly — it reads a request via ACCESSOR KERNELS
//! (`Server.body` / `Server.path` / `Server.method` / `Server.header` /
//! `Server.queryParam` / `Server.getCookie` / `Server.param`) and builds a
//! response via typed builder kernels (`Server.text` / `Server.json` /
//! `Server.html` / `Server.withStatus` / `Server.withHeader` /
//! `Server.redirect` / `Server.withCookie`). The `pub` fields on
//! `ServerRequest` / `ServerResponse` below exist solely so the accessor
//! functions in this file can read them — they are NOT part of the Ipê API.
//! `Route`/`Cookie` are opaque Ipê ADTs mapped the same way.

use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::entropy::EntropyError;
use crate::redact::{Redacted, redacting_debug};
use crate::system::RefusedText;

/// Ipe.Http.Server.Request — opaque parsed request handle.
// camelCase field names are required because accessor kernels (server_body,
// server_path, server_method, …) read these fields directly by name, and Ipê
// `req.<field>` access lowers to `(req).<field>.clone()` against the field
// types of `RequestFields` in `ipe_types` — so every field keeps its plain type.
// `build_request` populates every field exactly once at the axum boundary.
// Every field but the method is client-supplied data that can carry a credential
// (an `Authorization` header, a session cookie, a token in the path, query or
// body), so `Debug` masks it.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ServerRequest {
    pub method: String,
    pub path: String,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub params: HashMap<String, String>,
    pub query: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub remoteAddr: String,
}

crate::stringify::show_row!(
    "ServerRequest",
    Redacted(Reveal),
    [] ServerRequest,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |r, view| r.dev(view),
);

impl ServerRequest {
    /// The request as `Debug.log` prints it in a dev-posture build.
    ///
    /// Every field, except the values of the credential headers and of every
    /// cookie, which render as the marker.
    #[cfg(feature = "dev-posture")]
    fn dev(&self, view: crate::stringify::View) -> String {
        use crate::stringify::{IpeStringify, dev_cookie_names, dev_header_map, dev_record};
        dev_record(
            "ServerRequest",
            &[
                ("method", self.method.clone()),
                ("path", self.path.clone()),
                ("body", self.body.clone()),
                ("headers", dev_header_map(&self.headers)),
                ("params", self.params.ipe_render(view)),
                ("query", self.query.ipe_render(view)),
                (
                    "cookies",
                    dev_cookie_names(self.cookies.keys().map(String::as_str)),
                ),
                ("remoteAddr", self.remoteAddr.clone()),
            ],
        )
    }
}

redacting_debug!(ServerRequest {
    shown: [method],
    masked: [path, body, headers, params, query, cookies, remoteAddr],
});

/// Emitted `req.<field>` reads each field at the plain type `ipe_types`'
/// `RequestFields` table gives it (`String`, or `Dict String String` =
/// `HashMap<String, String>`); a field whose type changes breaks this build,
/// not a downstream cargo build of an emitted program.
#[allow(clippy::type_complexity)]
const _: fn(
    ServerRequest,
) -> (
    String,
    String,
    String,
    String,
    HashMap<String, String>,
    HashMap<String, String>,
    HashMap<String, String>,
    HashMap<String, String>,
) = |r| {
    (
        r.method,
        r.path,
        r.body,
        r.remoteAddr,
        r.headers,
        r.params,
        r.query,
        r.cookies,
    )
};

/// Ipe.Http.Server.Response — opaque response handle built by accessor kernels.
// camelCase field names are required because builder/emit kernels (server_text,
// server_with_status, to_axum_response, …) write/read these fields directly.
// These fields are NOT part of the Ipê API — Ipê code always uses builder kernels.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ServerResponse {
    pub status: i64,
    pub body: String,
    pub headers: HashMap<String, String>,
    pub contentType: String,
    /// Typed `Set-Cookie` header values (e.g. `"sid=abc; Path=/; HttpOnly"`),
    /// one entry per cookie. Kept separate from `headers` because `headers` is a
    /// `HashMap` (one value per key) and HTTP allows/requires MULTIPLE
    /// `Set-Cookie` response headers when a response needs to set more than one
    /// cookie (RFC 6265 §4.1 — Set-Cookie is the one header that must NEVER be
    /// comma-folded). A second caller writing into `headers["Set-Cookie"]` would
    /// silently clobber the first.
    pub cookies: Vec<SetCookie>,
}

crate::stringify::show_row!(
    "ServerResponse",
    Redacted(Reveal),
    [] ServerResponse,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |r, _| r.dev(),
);

impl ServerResponse {
    /// The response as `Debug.log` prints it in a dev-posture build.
    ///
    /// Every field, except the values of the credential headers and of every
    /// `Set-Cookie` line, which render as the marker.
    #[cfg(feature = "dev-posture")]
    fn dev(&self) -> String {
        use crate::stringify::{REDACTED_SHOW, dev_header_map, dev_record};
        let cookies: Vec<String> = self
            .cookies
            .iter()
            .map(|cookie| {
                cookie.as_str().split_once('=').map_or_else(
                    || REDACTED_SHOW.to_owned(),
                    |(name, _)| format!("{name}={REDACTED_SHOW}"),
                )
            })
            .collect();
        dev_record(
            "ServerResponse",
            &[
                ("status", self.status.to_string()),
                ("body", self.body.clone()),
                ("headers", dev_header_map(&self.headers)),
                ("contentType", self.contentType.clone()),
                ("cookies", format!("[{}]", cookies.join(" "))),
            ],
        )
    }
}

// The body, headers and `Set-Cookie` values can carry a session id or a token;
// the emitter builds this struct by field name, so the masking lives in `Debug`.
redacting_debug!(ServerResponse {
    shown: [status, contentType],
    masked: [body, headers, cookies],
});

/// Ipe.Http.Server.Cookie (opaque) — safe defaults applied at attach time.
// The value is the cookie's secret half (a session id, a token); the name is not.
#[derive(Clone, Debug)]
pub struct ServerCookie {
    pub name: CookieName,
    pub value: Redacted<CookieValue>,
}

crate::stringify::show_row!(
    "ServerCookie",
    Redacted(Reveal),
    [] ServerCookie,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |c, _| crate::stringify::dev_record(
        "ServerCookie",
        &[
            ("name", c.name.text().to_owned()),
            ("value", crate::stringify::REDACTED_SHOW.to_owned()),
        ],
    ),
);

/// A handler erased of its Ipê error type `E`: it awaits the Ipê task and maps
/// the result to either the response (Ok) or a 500 marker (Err). Erasing E here
/// keeps `ServerRoute` non-generic so it bridges to the non-generic Ipê `Route`.
type ErasedHandler = Arc<
    dyn Fn(ServerRequest) -> Pin<Box<dyn Future<Output = Result<ServerResponse, String>> + Send>>
        + Send
        + Sync,
>;

/// The Ipê `Handler` type (`Request -> Task Error Response`) reified as a
/// shareable, error-typed closure. The Rust codegen renders the `Handler` type
/// alias (and any `Request -> Task Error Response` arrow — e.g. the `h :
/// Handler` param of a middleware-wrapping closure `guarded h = …`) as exactly
/// this `Arc<dyn Fn>`, because a real route handler CAPTURES app state
/// (`handleRegister cfg db`) and a capturing closure cannot coerce to a bare
/// `fn` pointer.
pub type ServerHandler<E> = Arc<dyn Fn(ServerRequest) -> IpeTask<E, ServerResponse> + Send + Sync>;

/// Accept a route / middleware handler as EITHER a bare closure / fn item OR an
/// already-boxed `ServerHandler<E>` (the Arc the `Handler` alias renders as),
/// converging both to `ServerHandler<E>`. The two impls below can never overlap:
/// `Arc<dyn Fn>` does NOT itself implement `Fn`, so a value is covered by at most
/// one impl. This is what lets `server_get(path, my_fn)` (15-http-server, a bare
/// fn item) AND `wrap(guarded(handleDelete cfg db))` (36-composite-server, a
/// captured Arc handler threaded through middleware) both register without any
/// call-site wrapping in the generated code — the conversion is total and
/// allocation-free on the Arc path (it returns the Arc as-is).
pub trait IntoServerHandler<E> {
    fn into_server_handler(self) -> ServerHandler<E>;
}

impl<E, F> IntoServerHandler<E> for F
where
    F: Fn(ServerRequest) -> IpeTask<E, ServerResponse> + Send + Sync + 'static,
{
    fn into_server_handler(self) -> ServerHandler<E> {
        Arc::new(self)
    }
}

impl<E> IntoServerHandler<E> for ServerHandler<E> {
    fn into_server_handler(self) -> ServerHandler<E> {
        self
    }
}

// The codegen Arc-wraps a partial-applied route handler at its construction site
// (`Arc::new(move |req| handle_register(cfg, db, req))`), yielding an
// `Arc<{concrete closure}>` — distinct from both the blanket `F: Fn` impl (an
// `Arc` is not itself `Fn`) and the `Arc<dyn Fn>` (`ServerHandler<E>`) impl above
// (`dyn Fn` is `!Sized`, so it can't match this `Sized` `F`). Unsize it to
// `Arc<dyn Fn>` here so that form registers directly with `server_get` /
// `server_api`. The three impls cover pairwise-disjoint types.
impl<E, F> IntoServerHandler<E> for Arc<F>
where
    F: Fn(ServerRequest) -> IpeTask<E, ServerResponse> + Send + Sync + 'static,
{
    fn into_server_handler(self) -> ServerHandler<E> {
        self
    }
}

/// A `Server.mountApp` target: the mounted web app's router-builder, kept
/// behind `Arc<Mutex<Option<..>>>` so `RouteTarget`/`ServerRoute` stay `Clone`
/// (the builder is `FnOnce`, taken exactly once when `server_listen` nests it).
/// A second nest of the same route (a clone) finds `None` and skips — inert, no
/// panic. The `web` feature gates it because the builder produces an `axum`
/// router the mount nests; a server built without `web` never sees one.
#[cfg(feature = "web")]
type MountCell = Arc<std::sync::Mutex<Option<crate::tea::MountBuilder>>>;

/// Discriminated union over the possible route targets — replaces the
/// two `Option` fields so both-None is unrepresentable.
#[derive(Clone)]
enum RouteTarget {
    Handler(ErasedHandler),
    Static(String),
    /// `Server.mountApp prefix webApp`: nest the embedded web app's router
    /// under `path` (the prefix) on the shared server port.
    #[cfg(feature = "web")]
    MountWeb(MountCell),
}

/// Ipe.Http.Server.Route (opaque). Non-generic — see ErasedHandler.
#[derive(Clone)]
pub struct ServerRoute {
    pub method: String,
    pub path: String,
    target: RouteTarget, // private; was the two pub Options
}

crate::stringify::show_row!("ServerRoute", Internals, [] ServerRoute, |_| "<Ipe.Http.Server.Route>".to_owned());

// ─── handler erasure ──────────────────────────────────────────────────────

fn erase<E>(h: ServerHandler<E>) -> ErasedHandler
where
    E: Send + 'static,
{
    Arc::new(move |req: ServerRequest| {
        let task = h(req);
        Box::pin(async move {
            match task.await {
                IpeResult::Ok(resp) => Ok(resp),
                // The error detail is dropped at the boundary (-> 500). Handlers
                // wanting a typed error response should return an Ok response with
                // Server.withStatus instead; Err is for unexpected failures.
                IpeResult::Err(_) => Err("handler returned Err".to_string()),
            }
        }) as Pin<Box<dyn Future<Output = Result<ServerResponse, String>> + Send>>
    })
}

fn route<E, H>(method: &str, path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    ServerRoute {
        method: method.to_string(),
        path,
        target: RouteTarget::Handler(erase(h.into_server_handler())),
    }
}

// ─── routing kernels ──────────────────────────────────────────────────────

pub fn server_get<E, H>(path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    route("GET", path, h)
}

pub fn server_post<E, H>(path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    route("POST", path, h)
}

pub fn server_put<E, H>(path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    route("PUT", path, h)
}

pub fn server_delete<E, H>(path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    route("DELETE", path, h)
}

pub fn server_any<E, H>(path: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    route("ANY", path, h)
}

/// Server.api : String -> (Request -> Task Error Response) -> Route
///
/// `spec` is "METHOD /path" (e.g. "POST /v1/generate"); an omitted method
/// matches any verb. The CSRF exemption (`WithoutCsrf`) is a browser-session /
/// double-submit concern from Ipe.Web with no analogue on the Rust HTTP server,
/// so it has no effect here.
pub fn server_api<E, H>(spec: String, h: H) -> ServerRoute
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let (method, path) = api_spec_parts(&spec);
    route(&method, path, h)
}

/// Split a `Server.api` spec `"METHOD /path"` into its upper-cased method and
/// its trimmed path; a spec with no method before the first space is `ANY`
/// over the whole trimmed spec.
#[must_use]
pub fn api_spec_parts(spec: &str) -> (String, String) {
    // split_once is total by construction — no raw `spec[..idx]` range slice
    // (the restriction-lint footgun if the delimiter ever became multi-byte).
    match spec.split_once(' ') {
        Some((m, p)) if !m.is_empty() => (m.trim().to_string(), p.trim().to_string()),
        _ => ("ANY".to_string(), spec.trim().to_string()),
    }
}

/// Server.static : String -> String -> Route  (urlPrefix, dir)
pub fn server_static(path: String, dir: String) -> ServerRoute {
    ServerRoute {
        method: "GET".to_string(),
        path,
        target: RouteTarget::Static(dir),
    }
}

/// `Server.mountApp : String -> WebApp -> Route` — mount a `Web.embed` handle
/// at the `prefix` path into the shared server Router. The embedded app runs on
/// the SAME listener as the sibling `Server.get`/`post` routes (one port). The
/// `WebApp` arg is a `Web.embed` handle carrying a router-builder; the type
/// system (`mountApp : String -> WebApp -> Route`) guarantees only a `WebApp`
/// reaches here, so a wrong-shape app is already a compile error.
///
/// A `Web.tea` (standalone) handle would carry no mount builder (`None`); that
/// is unreachable for well-typed source that reached `mountApp` via `Web.embed`,
/// but is handled fail-closed anyway (the route becomes inert — it nests
/// nothing — never a panic).
#[cfg(feature = "web")]
pub fn server_mount_app(prefix: String, app: crate::tea::WebApp) -> ServerRoute {
    let cell: MountCell = Arc::new(std::sync::Mutex::new(app.into_mount_builder()));
    ServerRoute {
        method: "MOUNT".to_string(),
        path: prefix,
        target: RouteTarget::MountWeb(cell),
    }
}

// ─── authenticated routes (fail-closed; sole Principal minter) ─────────────
//
// Token verification runs through `crate::auth`, so the authed surface compiles
// only when the `jwt` feature is also selected. A program that uses `getAuthed`
// pulls `jwt` into the emitted project's features.

/// Ipe.Server.TokenSource — where the auth middleware reads the session token.
#[cfg(feature = "jwt")]
#[derive(Clone, Debug)]
pub enum TokenSource {
    /// `Authorization: Bearer <token>`.
    BearerHeader,
    /// A named request cookie carrying the token.
    Cookie(CookieName),
}

#[cfg(feature = "jwt")]
crate::stringify::show_row!(
    "TokenSource",
    Redacted(Reveal),
    [] TokenSource,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |s, _| s.dev(),
);

#[cfg(feature = "jwt")]
impl TokenSource {
    /// The token source as `Debug.log` prints it in a dev-posture build: its
    /// constructor and the cookie name it reads.
    #[cfg(feature = "dev-posture")]
    fn dev(&self) -> String {
        match self {
            Self::BearerHeader => "BearerHeader".to_owned(),
            Self::Cookie(name) => format!("Cookie {}", name.text()),
        }
    }
}

/// Ipe.Server.AuthConfig (opaque) — the secret, token source, claim key, and
/// revocation mode the middleware uses. Built by [`server_auth_config`]; the
/// only value the authed-route kernels accept. The revocation mode defaults to
/// `Off` and is set by [`server_with_revocation`].
#[cfg(feature = "jwt")]
#[derive(Clone)]
pub struct AuthConfig {
    secret: crate::secret::Secret,
    source: TokenSource,
    subject_claim: String,
    revocation_mode: crate::app_config::RevocationMode,
}

#[cfg(feature = "jwt")]
crate::stringify::show_row!(
    "AuthConfig",
    Redacted(Reveal),
    [] AuthConfig,
    shown: |_| crate::stringify::REDACTED_SHOW.to_owned(),
    dev: |c, _| c.dev(),
);

#[cfg(feature = "jwt")]
impl AuthConfig {
    /// The configuration as `Debug.log` prints it in a dev-posture build.
    ///
    /// Every field but the signing secret, which renders as the marker.
    #[cfg(feature = "dev-posture")]
    fn dev(&self) -> String {
        use crate::app_config::RevocationMode;
        let revocation = match self.revocation_mode {
            RevocationMode::Off => "Off",
            RevocationMode::Store => "Store",
        };
        crate::stringify::dev_record(
            "AuthConfig",
            &[
                ("secret", crate::stringify::REDACTED_SHOW.to_owned()),
                ("source", self.source.dev()),
                ("subjectClaim", self.subject_claim.clone()),
                ("revocationMode", revocation.to_owned()),
            ],
        )
    }
}

#[cfg(feature = "jwt")]
/// Ipe.Server.authConfig : Secret -> TokenSource -> AuthConfig. The subject
/// claim key defaults to the JWT standard `"sub"`. Revocation defaults to `Off`.
#[must_use]
pub fn server_auth_config(secret: crate::secret::Secret, source: TokenSource) -> AuthConfig {
    AuthConfig {
        secret,
        source,
        subject_claim: "sub".to_string(),
        revocation_mode: crate::app_config::RevocationMode::Off,
    }
}

#[cfg(feature = "jwt")]
/// Ipe.Server.withRevocation : RevocationMode -> AuthConfig -> AuthConfig.
/// Arms (or keeps armed) the per-request revocation gate on this config.
/// The mode is supplied as a raw tag: `0` = `Off`, `1` = `Store`; out-of-range
/// falls closed to `Store`. Stricter-only: once `Store`, a subsequent `Off` is
/// a no-op, and `IPE_AUTH_REVOCATION=off` cannot lower it either.
#[must_use]
pub fn server_with_revocation(mode_tag: i64, mut cfg: AuthConfig) -> AuthConfig {
    use crate::app_config::RevocationMode;
    let requested = match mode_tag {
        0 => RevocationMode::Off,
        _ => RevocationMode::Store,
    };
    // Stricter-only: Store wins over Off.
    if cfg.revocation_mode != RevocationMode::Store {
        cfg.revocation_mode = requested;
    }
    cfg
}

#[cfg(feature = "jwt")]
/// Ipe.Server.bearerToken : TokenSource. Reads the token from the
/// `Authorization: Bearer` header.
#[must_use]
pub fn server_token_bearer() -> TokenSource {
    TokenSource::BearerHeader
}

#[cfg(feature = "jwt")]
/// Ipe.Server.cookieToken : String -> Result Error TokenSource. Reads the token
/// from the named request cookie; an empty name is an `InvalidInput` error, so a
/// cookie source always names a cookie a request can carry.
#[must_use]
pub fn server_cookie_token(name: String) -> IpeResult<IpeError, TokenSource> {
    match CookieName::parse(&name) {
        Some(name) => IpeResult::Ok(TokenSource::Cookie(name)),
        None => IpeResult::Err(IpeError::invalid_input(
            "Server.cookieToken: a cookie name must not be empty".to_owned(),
        )),
    }
}

#[cfg(feature = "jwt")]
/// Read the raw token string from the request per the configured source, or
/// `None` when it is absent/empty. A `Bearer` scheme prefix is matched
/// case-insensitively (RFC 7235 auth-scheme is case-insensitive); any other
/// scheme, or a missing header/cookie, yields `None` so the caller fails closed.
fn read_token(source: &TokenSource, req: &ServerRequest) -> Option<String> {
    match source {
        TokenSource::BearerHeader => {
            let raw = header_ci(&req.headers, "authorization")?;
            let rest = raw.strip_prefix("Bearer ").or_else(|| {
                raw.get(..7)
                    .filter(|p| p.eq_ignore_ascii_case("bearer "))
                    .and_then(|_| raw.get(7..))
            })?;
            let tok = rest.trim();
            (!tok.is_empty()).then(|| tok.to_string())
        }
        TokenSource::Cookie(name) => req
            .cookies
            .get(name.text())
            .filter(|v| !v.is_empty())
            .map(ToString::to_string),
    }
}

#[cfg(feature = "jwt")]
/// A `401 Unauthorized` response. The body carries no verification detail (a
/// specific reason would be an oracle to an attacker probing tokens).
fn unauthorized() -> ServerResponse {
    plain_resp(401, "unauthorized", &[("WWW-Authenticate", "Bearer")])
}

#[cfg(feature = "jwt")]
/// Build the `Set-Cookie` value for a re-issued session token. Preserves all
/// security attributes of the original session cookie: `__Host-`/Secure,
/// `Path=/`, `HttpOnly`, and `SameSite`. The cookie name must be the same name
/// that the request carried the token under so the browser replaces the existing
/// cookie entry rather than creating a duplicate.
///
/// `is_https` must be pre-captured from the incoming request's headers
/// BEFORE the request is moved into the handler — mirrors the combined gate
/// in `page_response` (`csrf::cookies_secure() || request_is_https(headers)`):
/// a re-issued cookie must never be less-Secure than the initial session cookie.
fn reissue_set_cookie(
    cookie_name: &CookieName,
    token: &str,
    slide_window_secs: u64,
    is_https: bool,
) -> SetCookie {
    // The cookie-security signal lives in `web::csrf` for a program that emits the
    // web surface; a server-only program (no `web` module) falls back to the
    // process `Secure` floor. `feature = "web"` is the exact condition under which
    // `crate::web` is present, so the reference is compiled out when it is absent.
    #[cfg(feature = "web")]
    let base_secure = crate::web::csrf::cookies_secure();
    #[cfg(not(feature = "web"))]
    let base_secure = cookie_secure_floor();
    reissue_set_cookie_with(
        cookie_name,
        token,
        slide_window_secs,
        base_secure || is_https,
    )
}

#[cfg(feature = "jwt")]
/// [`reissue_set_cookie`] under an explicit `Secure` decision.
fn reissue_set_cookie_with(
    cookie_name: &CookieName,
    token: &str,
    slide_window_secs: u64,
    secure: bool,
) -> SetCookie {
    // A server-only program has no double-submit CSRF check, so its session
    // cookie stays `SameSite=Lax` even when `frame-ancestors` admits embedding.
    #[cfg(feature = "web")]
    let embeddable = crate::web::csrf::frame_ancestors().is_some();
    #[cfg(not(feature = "web"))]
    let embeddable = false;
    let same_site = if embeddable {
        SameSite::None
    } else {
        SameSite::Lax
    };
    SetCookie::new(
        cookie_name,
        &CookieValue::encode(token),
        CookieAttributes {
            path: CookiePath::root(),
            http_only: true,
            same_site,
            secure,
            max_age_secs: Some(slide_window_secs),
        },
    )
}

#[cfg(feature = "jwt")]
/// The shared authed-route builder. Wraps the caller's
/// `Request -> Principal -> Task Response` handler in fail-closed middleware
/// that runs BEFORE the handler: it reads the token, verifies it, checks the
/// revocation store (when armed), extracts the subject claim, and mints the
/// `Principal` — dispatching to the handler only on full success, and answering
/// `401` at the first failing step. This is the sole site that mints a `Principal`.
///
/// Revocation gate (when `RevocationMode::Store`): the verified claims pass
/// [`ArmedGate::admit`](crate::revocation::ArmedGate::admit) AFTER signature +
/// expiry verification and BEFORE the `Principal` is minted, and the admitted
/// credential is bound to the request. A token with no `jti` or no lifetime
/// bound, a revoked token, a store that cannot answer, and a full binding set
/// all answer `401`. The mode is the stricter of the config's and
/// `IPE_AUTH_REVOCATION`'s, read once when the route is built: the env arms the
/// gate and never disarms it. Building an armed route arms the whole process
/// ([`arm_process`](crate::revocation::arm_process)), so `Auth.verifyToken`
/// checks the store too.
///
/// Sliding re-issue: for cookie-based token sources, when the verified token is
/// past its re-issue threshold (`exp - slide_window/2`) and the absolute cap has
/// not been reached, a fresh token is minted and attached via `Set-Cookie`.
/// `iat`, `cap`, and `jti` are carried verbatim from the verified-origin
/// `ReissueContext` — a client cannot move the cap outward or change the session id.
fn authed_route<E, F>(method: &str, path: String, cfg: AuthConfig, handler: F) -> ServerRoute
where
    E: Send + 'static,
    F: Fn(ServerRequest, crate::principal::Principal) -> IpeTask<E, ServerResponse>
        + Send
        + Sync
        + 'static,
{
    let handler = Arc::new(handler);
    let route_gate = crate::revocation::ArmedGate::resolve(
        cfg.revocation_mode
            .stricter(crate::app_config::env_revocation_floor()),
    );
    if route_gate.is_some() {
        crate::revocation::arm_process();
    }
    let guarded = move |req: ServerRequest| -> IpeTask<E, ServerResponse> {
        // Snapshot the request-scoped TLS signal BEFORE `req` is moved into
        // the async block — same technique as `middleware_with_csrf`. The bool
        // is `Copy`, so this is a zero-cost capture.
        let is_https = request_is_https(&req.headers);
        let cfg = cfg.clone();
        let handler = Arc::clone(&handler);
        Box::pin(async move {
            let Some(token) = read_token(&cfg.source, &req) else {
                return ok_res(unauthorized());
            };
            let secret = crate::secret::secret_reveal(cfg.secret.clone());
            let Ok(claims) = crate::auth::verify_claims(&secret, &token) else {
                return ok_res(unauthorized());
            };
            let Some(subject) = claims.get(&cfg.subject_claim).filter(|s| !s.is_empty()) else {
                return ok_res(unauthorized());
            };

            // Revocation gate — only when armed. Runs AFTER token verification
            // and BEFORE `Principal` mint; every denial answers `401`, and so
            // does a dispatch with no request binding set to hold the credential.
            if let Some(gate) = route_gate {
                let Ok(credential) = gate.admit(&claims, &cfg.subject_claim) else {
                    return ok_res(unauthorized());
                };
                let Some(bindings) = request_bindings() else {
                    return ok_res(unauthorized());
                };
                if crate::revocation::bind_shared(&bindings, credential).is_err() {
                    return ok_res(unauthorized());
                }
            }

            // Carry the verified claims into the principal so the Ipê read
            // accessors (`Auth.claim` / `Auth.hasRole` / `Auth.memberOf`) can
            // answer principal-side questions. These are the token's own
            // verified payload — the same bearer-readable strings the caller
            // presented — so nothing new is exposed. `BTreeMap` keeps the
            // read-back deterministic.
            let principal = crate::principal::principal_mint_with_claims(
                subject.to_owned(),
                claims
                    .iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            );

            // Sliding re-issue — cookie-source only (bearer tokens are API
            // credentials; the client manages re-issue itself via re-auth).
            let reissue_cookie: Option<SetCookie> = if let TokenSource::Cookie(ref name) =
                cfg.source
            {
                if let Some(ctx) = crate::auth::reissue_context_from_claims(&claims) {
                    // A malformed window refuses the request rather than
                    // re-issuing under an unknown bound; the detail stays out of
                    // the response.
                    let Ok(slide_window_secs) = crate::app_config::resolve_auth_slide_window()
                    else {
                        return ok_res(plain_resp(503, "service unavailable", &[]));
                    };
                    let slide_i64 = i64::try_from(slide_window_secs).unwrap_or(i64::MAX);
                    let now = crate::jwt::now_unix_seconds();
                    // Throttle: re-issue only once past exp - slide_window/2.
                    // `exp` is the typed value `verify_claims` read.
                    let past_threshold = now > claims.times().exp().saturating_sub(slide_i64 / 2);
                    if past_threshold && now < ctx.cap {
                        // Extra claims to carry into the re-issued token (all
                        // verified claims except the time anchors and subject —
                        // those come from the ReissueContext).
                        let extra: HashMap<String, String> = claims
                            .iter()
                            .filter(|(k, _)| {
                                // Time anchors and session-identity fields come from
                                // ReissueContext verbatim; skip them in extra_claims.
                                !["exp", "iat", "cap", "jti", "sub"].contains(k)
                            })
                            .map(|(k, v)| (k.to_owned(), v.to_owned()))
                            .collect();
                        match crate::auth::auth_reissue_token::<String>(
                            &secret, &ctx, extra, slide_i64,
                        ) {
                            Some(IpeResult::Ok(new_token)) => Some(reissue_set_cookie(
                                name,
                                &new_token,
                                slide_window_secs,
                                is_https,
                            )),
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let mut resp = handler(req, principal).await;
            // Attach the re-issue cookie when warranted. The handler returns an
            // IpeResult<E, ServerResponse>; we append the Set-Cookie to the Ok path.
            if let (IpeResult::Ok(r), Some(cookie)) = (&mut resp, reissue_cookie) {
                r.cookies.push(cookie);
            }
            resp
        })
    };
    route::<E, _>(method, path, guarded)
}

#[cfg(feature = "jwt")]
/// Server.getAuthed : String -> AuthConfig -> (Request -> Principal -> Task Response) -> Route
pub fn server_get_authed<E, F>(path: String, cfg: AuthConfig, handler: F) -> ServerRoute
where
    E: Send + 'static,
    F: Fn(ServerRequest, crate::principal::Principal) -> IpeTask<E, ServerResponse>
        + Send
        + Sync
        + 'static,
{
    authed_route("GET", path, cfg, handler)
}

#[cfg(feature = "jwt")]
/// Server.postAuthed : String -> AuthConfig -> (Request -> Principal -> Task Response) -> Route
pub fn server_post_authed<E, F>(path: String, cfg: AuthConfig, handler: F) -> ServerRoute
where
    E: Send + 'static,
    F: Fn(ServerRequest, crate::principal::Principal) -> IpeTask<E, ServerResponse>
        + Send
        + Sync
        + 'static,
{
    authed_route("POST", path, cfg, handler)
}

#[cfg(feature = "jwt")]
/// Server.putAuthed : String -> AuthConfig -> (Request -> Principal -> Task Response) -> Route
pub fn server_put_authed<E, F>(path: String, cfg: AuthConfig, handler: F) -> ServerRoute
where
    E: Send + 'static,
    F: Fn(ServerRequest, crate::principal::Principal) -> IpeTask<E, ServerResponse>
        + Send
        + Sync
        + 'static,
{
    authed_route("PUT", path, cfg, handler)
}

#[cfg(feature = "jwt")]
/// Server.deleteAuthed : String -> AuthConfig -> (Request -> Principal -> Task Response) -> Route
pub fn server_delete_authed<E, F>(path: String, cfg: AuthConfig, handler: F) -> ServerRoute
where
    E: Send + 'static,
    F: Fn(ServerRequest, crate::principal::Principal) -> IpeTask<E, ServerResponse>
        + Send
        + Sync
        + 'static,
{
    authed_route("DELETE", path, cfg, handler)
}

// ─── response builders (pure) ─────────────────────────────────────────────

fn resp(status: i64, body: String, ct: &str) -> ServerResponse {
    ServerResponse {
        status,
        body,
        headers: HashMap::new(),
        contentType: ct.to_string(),
        cookies: Vec::new(),
    }
}

pub fn server_text(body: String) -> ServerResponse {
    resp(200, body, "text/plain")
}
pub fn server_json(body: String) -> ServerResponse {
    resp(200, body, "application/json")
}
pub fn server_html(body: String) -> ServerResponse {
    resp(200, body, "text/html")
}

pub fn server_with_status(status: i64, mut r: ServerResponse) -> ServerResponse {
    r.status = status;
    r
}
/// Why a response header has no representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeaderRefusal {
    /// The name is not an RFC 7230 `token`.
    Name,
    /// The value holds a control byte (CR, LF, NUL, ...) or a non-ASCII byte.
    Value,
    /// `Set-Cookie`, in any case: every cookie line is built by `SetCookie`.
    SetCookie,
    /// `Content-Length` or `Transfer-Encoding`, in any case: the server frames
    /// the body it sends, so a handler's value could only disagree with it.
    Framing,
}

impl HeaderRefusal {
    /// The refusal as the `Server.withHeader` error message; it never echoes the input.
    const fn message(self) -> &'static str {
        match self {
            Self::Name => "Server.withHeader: the header name is not an HTTP token",
            Self::Value => {
                "Server.withHeader: the header value holds a control character (such as CR or LF) or a non-ASCII character"
            }
            Self::SetCookie => {
                "Server.withHeader: `Set-Cookie` is not a raw header; set a cookie with `Server.withCookie` and `Server.cookie`"
            }
            Self::Framing => {
                "Server.withHeader: `Content-Length` and `Transfer-Encoding` are set by the server from the body it sends"
            }
        }
    }
}

/// Parse one response header into its typed name and value.
///
/// `Set-Cookie` in any case is refused, so a cookie line is only ever the one
/// `SetCookie` builds from typed parts. `Content-Length` and
/// `Transfer-Encoding` in any case are refused, so the body framing is only
/// ever the server's own.
fn parse_response_header(
    name: &str,
    value: &str,
) -> Result<(axum::http::HeaderName, axum::http::HeaderValue), HeaderRefusal> {
    let name =
        axum::http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| HeaderRefusal::Name)?;
    if name == axum::http::header::SET_COOKIE {
        return Err(HeaderRefusal::SetCookie);
    }
    if name == axum::http::header::CONTENT_LENGTH || name == axum::http::header::TRANSFER_ENCODING {
        return Err(HeaderRefusal::Framing);
    }
    if !value.is_ascii() {
        return Err(HeaderRefusal::Value);
    }
    let value = axum::http::HeaderValue::from_str(value).map_err(|_| HeaderRefusal::Value)?;
    Ok((name, value))
}

/// `Server.withHeader : String -> String -> Response -> Result Error Response`.
///
/// The header enters the response only when its name is a `token` other than
/// `Set-Cookie`, `Content-Length` and `Transfer-Encoding` and its value a
/// visible-ASCII header value; any other header is an `InvalidInput` error.
/// It replaces every header of the same name in any case, so the response
/// holds one value per header name.
#[must_use]
pub fn server_with_header(
    k: String,
    v: String,
    mut r: ServerResponse,
) -> IpeResult<IpeError, ServerResponse> {
    match parse_response_header(&k, &v) {
        Ok(_) => {
            set_header_replacing(&mut r.headers, k, v);
            IpeResult::Ok(r)
        }
        Err(refusal) => IpeResult::Err(IpeError::invalid_input(refusal.message().to_owned())),
    }
}

/// Sets header `name` to `value` in a response's headers, replacing every
/// header of the same name in any case, so the map holds one value per header
/// name. Every runtime write of a response header by name goes through here.
fn set_header_replacing(headers: &mut HashMap<String, String>, name: String, value: String) {
    headers.retain(|k, _| !k.eq_ignore_ascii_case(&name));
    headers.insert(name, value);
}

/// Every value of header `name` in any case, joined by `, ` in name order so
/// the result does not depend on map iteration order; `None` when absent.
fn header_values_ci(headers: &HashMap<String, String>, name: &str) -> Option<String> {
    let mut found: Vec<(&String, &String)> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .collect();
    if found.is_empty() {
        return None;
    }
    found.sort();
    Some(
        found
            .into_iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    )
}

pub use response_head::ServerResponseHead;
use response_head::{ServerDelivery, assemble_response_head};

/// The one assembly of a response's status and headers, for every delivery.
///
/// A [`ServerResponseHead`] has no constructor but [`assemble_response_head`],
/// so a buffered and a streamed response carry the same parsed handler
/// headers, `Set-Cookie` lines and security headers, and refuse alike.
mod response_head {
    use super::{ServerResponse, parse_response_header};
    use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};

    /// How a response body reaches the client.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ServerDelivery {
        /// The whole body in one piece.
        Buffered,
        /// The body chunk by chunk over a held connection.
        Streamed,
    }

    impl ServerDelivery {
        /// The headers this delivery adds when the handler has not set them.
        fn default_headers(self) -> [Option<(HeaderName, HeaderValue)>; 2] {
            match self {
                Self::Buffered => [None, None],
                // A proxy forwards each chunk as it arrives, and a streamed
                // body is never replayed from a cache.
                Self::Streamed => [
                    Some((
                        const { HeaderName::from_static("x-accel-buffering") },
                        const { HeaderValue::from_static("no") },
                    )),
                    Some((
                        header::CACHE_CONTROL,
                        const { HeaderValue::from_static("no-cache") },
                    )),
                ],
            }
        }
    }

    /// Why a response has no head to send; every refusal answers `500`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum HeadRefusal {
        /// A handler header has no representation (see `parse_response_header`),
        /// or names a header another handler header names in another case.
        Header,
        /// The response content type is not a header value.
        ContentType,
        /// A cookie line is not a header value.
        Cookie,
        /// The framing policy (`IPE_WEB_FRAME_ANCESTORS`) was refused.
        FramingPolicy,
        /// A security header is not a header line.
        SecurityHeader,
        /// The head holds more header names than a header map can.
        Oversize,
    }

    /// A response status and header set, built only by [`assemble_response_head`].
    pub struct ServerResponseHead {
        status: StatusCode,
        headers: HeaderMap,
    }

    // Header values can carry a session id or a token: only the status is shown.
    impl std::fmt::Debug for ServerResponseHead {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ServerResponseHead")
                .field("status", &self.status)
                .finish_non_exhaustive()
        }
    }

    impl ServerResponseHead {
        /// Whether the head declares an HTML body.
        #[must_use]
        pub fn is_html(&self) -> bool {
            self.headers
                .get(header::CONTENT_TYPE)
                .is_some_and(|v| v.as_bytes().starts_with(b"text/html"))
        }

        /// The response with this head over `body`.
        #[must_use]
        pub fn into_response(self, body: axum::body::Body) -> axum::response::Response {
            let mut resp = axum::response::Response::new(body);
            *resp.status_mut() = self.status;
            *resp.headers_mut() = self.headers;
            resp
        }
    }

    /// Assemble the head of `r` for `delivery` under the read security headers.
    ///
    /// Every handler header is parsed again, whatever built it: a `Response`
    /// record update can carry headers `Server.withHeader` never saw. A handler
    /// `content-type` header wins over `r.contentType`. Each `Set-Cookie` line
    /// is its own header, never comma-folded (RFC 6265 §4.1). A security or
    /// delivery header is added only when the handler has not set it.
    ///
    /// # Errors
    ///
    /// A [`HeadRefusal`] for a handler header, content type, cookie line or
    /// security header with no representation, for two handler headers of one
    /// name, for more header names than a header map holds, or for a refused
    /// framing policy: no response ships without its framing policy, with a
    /// raw line, or with a header whose value depends on iteration order.
    pub fn assemble_response_head(
        r: &ServerResponse,
        delivery: ServerDelivery,
        security: Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>,
    ) -> Result<ServerResponseHead, HeadRefusal> {
        let security = security.map_err(|_| HeadRefusal::FramingPolicy)?;
        // An out-of-range Ipê status is clamped into the HTTP range first.
        let status = u16::try_from(r.status.clamp(100, 599))
            .ok()
            .and_then(|s| StatusCode::from_u16(s).ok())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut headers = HeaderMap::new();
        // One value per handler header name: a second spelling of a name is
        // refused, never appended in `HashMap` iteration order.
        for (k, v) in &r.headers {
            let (name, value) = parse_response_header(k, v).map_err(|_| HeadRefusal::Header)?;
            if headers.contains_key(&name) {
                return Err(HeadRefusal::Header);
            }
            headers
                .try_insert(name, value)
                .map_err(|_| HeadRefusal::Oversize)?;
        }
        if !r.contentType.is_empty() && !headers.contains_key(header::CONTENT_TYPE) {
            let (_, value) = parse_response_header("content-type", &r.contentType)
                .map_err(|_| HeadRefusal::ContentType)?;
            headers
                .try_insert(header::CONTENT_TYPE, value)
                .map_err(|_| HeadRefusal::Oversize)?;
        }
        for cookie in &r.cookies {
            let value = cookie.header_value().ok_or(HeadRefusal::Cookie)?;
            headers
                .try_append(header::SET_COOKIE, value)
                .map_err(|_| HeadRefusal::Oversize)?;
        }
        for (name, value) in security {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| HeadRefusal::SecurityHeader)?;
            if !headers.contains_key(&name) {
                let value =
                    HeaderValue::from_str(&value).map_err(|_| HeadRefusal::SecurityHeader)?;
                headers
                    .try_insert(name, value)
                    .map_err(|_| HeadRefusal::Oversize)?;
            }
        }
        for (name, value) in delivery.default_headers().into_iter().flatten() {
            if !headers.contains_key(&name) {
                headers
                    .try_insert(name, value)
                    .map_err(|_| HeadRefusal::Oversize)?;
            }
        }
        Ok(ServerResponseHead { status, headers })
    }
}

/// Bytes a `Location` value never holds raw.
///
/// CTLs, space, non-ASCII (always encoded by `utf8_percent_encode`) and the
/// ASCII characters RFC 3986 neither reserves nor leaves unreserved. `%` and
/// every reserved character are kept, so an already-encoded URI is unchanged.
const LOCATION_ESCAPE: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// Ipê `redirect : String -> Response` — a 302 to `location`.
///
/// `location` is percent-encoded into a visible-ASCII URI reference, so every
/// redirect is a valid response. The status is fixed; `withStatus` overrides it.
#[must_use]
pub fn server_redirect(location: String) -> ServerResponse {
    let mut r = resp(302, String::new(), "text/plain");
    set_header_replacing(
        &mut r.headers,
        "Location".to_owned(),
        percent_encoding::utf8_percent_encode(&location, LOCATION_ESCAPE).to_string(),
    );
    r
}

// ─── request accessors (pure) ─────────────────────────────────────────────

pub fn server_param(name: String, req: ServerRequest) -> IpeMaybe<String> {
    match req.params.get(&name) {
        Some(v) => IpeMaybe::Just(v.clone()),
        None => IpeMaybe::Nothing,
    }
}
pub fn server_query_param(name: String, req: ServerRequest) -> IpeMaybe<String> {
    match req.query.get(&name) {
        Some(v) => IpeMaybe::Just(v.clone()),
        None => IpeMaybe::Nothing,
    }
}
pub fn server_header(name: String, req: ServerRequest) -> IpeMaybe<String> {
    //  `r.Header.Get` canonicalises the lookup key, so `Server.header
    // "content-type"` and `"Content-Type"` both resolve. `build_request` stores
    // request headers under the same canonical key, so this lookup is
    // case-insensitive with respect to the caller's casing.
    match req
        .headers
        .get(&crate::http_header::canonical_header(&name))
    {
        Some(v) => IpeMaybe::Just(v.clone()),
        None => IpeMaybe::Nothing,
    }
}
/// `Server.getCookie name req` — the decoded value of the cookie `name`.
///
/// `req.cookies` holds only pairs whose wire name is the encoding of their
/// decoded name and whose value decodes, so this matches exactly the cookie
/// `Server.cookie name` writes.
pub fn server_get_cookie(name: String, req: ServerRequest) -> IpeMaybe<String> {
    match req.cookies.get(&name) {
        Some(v) => IpeMaybe::Just(v.clone()),
        None => IpeMaybe::Nothing,
    }
}

// These three are total (every well-formed request has a body, path, and
// method — they are populated unconditionally by `build_request`), so they
// return plain `String`, NOT `IpeMaybe<String>`.  analogous
// accessors return the raw parsed string values with no Maybe wrapper.
pub fn server_body(req: ServerRequest) -> String {
    req.body
}
pub fn server_path(req: ServerRequest) -> String {
    req.path
}
pub fn server_method(req: ServerRequest) -> String {
    req.method
}

// ─── cookies ──────────────────────────────────────────────────────────────

pub use crate::http_header::cookie::{CookieName, CookieValue, RuntimeCookie, request_cookies};
pub use cookie_octets::{CookieAttributes, CookiePath, SameSite, SetCookie};

/// The `Set-Cookie` line grammar, held in types.
///
/// A [`SetCookie`] line is assembled only from a [`CookieName`], a
/// [`CookieValue`] (the shared RFC 6265 grammar in `http_header::cookie`) and a
/// typed attribute set, so every `Set-Cookie` value the server emits is a valid
/// header value and carries no attribute or line the caller supplied.
mod cookie_octets {
    use super::{CookieName, CookieValue};
    use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

    /// Bytes outside RFC 6265 `av-octet` (a `Path` attribute value): CTLs and `;`.
    const NOT_AV_OCTET: &AsciiSet = &CONTROLS.add(b';');

    /// The `SameSite` attribute of a `Set-Cookie` line.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SameSite {
        Lax,
        Strict,
        None,
    }

    impl SameSite {
        const fn as_str(self) -> &'static str {
            match self {
                Self::Lax => "Lax",
                Self::Strict => "Strict",
                Self::None => "None",
            }
        }
    }

    /// A `Path` attribute value: starts with `/` and holds only `av-octet` bytes.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CookiePath(String);

    impl CookiePath {
        /// The root path `/`.
        #[must_use]
        pub fn root() -> Self {
            Self("/".to_owned())
        }

        /// Parse `raw`, percent-encoding every byte that is not an `av-octet`.
        ///
        /// A value without a leading `/` gets one, so the browser never falls
        /// back to the request's default path.
        #[must_use]
        pub fn encode(raw: &str) -> Self {
            let encoded = utf8_percent_encode(raw, NOT_AV_OCTET).to_string();
            if encoded.starts_with('/') {
                Self(encoded)
            } else {
                Self(format!("/{encoded}"))
            }
        }

        /// The encoded path.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// The attributes of a `Set-Cookie` line.
    ///
    /// `SameSite=None` always renders `Secure`: a browser drops a cross-site
    /// cookie that lacks it, so the pair is never emitted apart.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct CookieAttributes {
        pub path: CookiePath,
        pub http_only: bool,
        pub same_site: SameSite,
        pub secure: bool,
        pub max_age_secs: Option<u64>,
    }

    /// One `Set-Cookie` header value built from typed parts.
    ///
    /// The line carries the cookie's value (a session id, a token), so its
    /// `Debug` prints [`crate::redact::REDACTED`], never the line.
    #[derive(Clone, PartialEq, Eq)]
    pub struct SetCookie(String);

    impl std::fmt::Debug for SetCookie {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_tuple("SetCookie")
                .field(&crate::redact::Redacted::new(()))
                .finish()
        }
    }

    impl SetCookie {
        /// Render `name=value; Path=<path>` and then `attributes` in a fixed order.
        #[must_use]
        pub fn new(name: &CookieName, value: &CookieValue, attributes: CookieAttributes) -> Self {
            let http_only = if attributes.http_only {
                "; HttpOnly"
            } else {
                ""
            };
            let same_site = attributes.same_site.as_str();
            let secure = if attributes.secure || attributes.same_site == SameSite::None {
                "; Secure"
            } else {
                ""
            };
            let max_age = attributes
                .max_age_secs
                .map_or_else(String::new, |secs| format!("; Max-Age={secs}"));
            Self(format!(
                "{}={}; Path={}{http_only}; SameSite={same_site}{secure}{max_age}",
                name.as_str(),
                value.as_str(),
                attributes.path.as_str()
            ))
        }

        /// The header value.
        #[must_use]
        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// The line as a `Set-Cookie` header value.
        ///
        /// The one place a cookie line becomes a header: every response path
        /// appends this, and answers `500` on `None` rather than send the
        /// response without the cookie.
        #[must_use]
        pub fn header_value(&self) -> Option<axum::http::HeaderValue> {
            axum::http::HeaderValue::from_str(&self.0).ok()
        }

        /// A line holding `raw` verbatim, bypassing the grammar.
        #[cfg(test)]
        #[must_use]
        pub fn unchecked_for_test(raw: &str) -> Self {
            Self(raw.to_owned())
        }
    }

    impl std::ops::Deref for SetCookie {
        type Target = str;

        fn deref(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Display for SetCookie {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
}

/// `Server.cookie : String -> String -> Result Error Cookie`.
///
/// Parses both fields into their cookie grammar; an empty name is an
/// `InvalidInput` error, so a `Cookie` always carries a non-empty name.
#[must_use]
pub fn server_cookie(name: String, value: String) -> IpeResult<IpeError, ServerCookie> {
    match CookieName::parse(&name) {
        Some(name) => IpeResult::Ok(ServerCookie {
            name,
            value: Redacted::new(CookieValue::encode(&value)),
        }),
        None => IpeResult::Err(IpeError::invalid_input(
            "Server.cookie: a cookie name must not be empty".to_owned(),
        )),
    }
}

/// `Server.withCookie` — attach `c` with `Path=/; HttpOnly; SameSite=Lax`.
///
/// `Secure` is added unless the process holds a dev intent (a dev-intent
/// binary in a dev posture), so an auth/session cookie never crosses a
/// cleartext hop; only a dev-intent process omits it, so cookies work over
/// plain-http localhost. The gate is `cookie_secure_floor`.
#[must_use]
pub fn server_with_cookie(c: ServerCookie, mut r: ServerResponse) -> ServerResponse {
    r.cookies.push(SetCookie::new(
        &c.name,
        &c.value,
        CookieAttributes {
            path: CookiePath::root(),
            http_only: true,
            same_site: SameSite::Lax,
            secure: cookie_secure_floor(),
            max_age_secs: None,
        },
    ));
    r
}

// ─── listen + axum adapter (step 4) ───────────────────────────────────────

/// Request-body cap: `IPE_WEB_MAX_BODY_BYTES`, default 32 MiB.
const MAX_BODY_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WEB_MAX_BODY_BYTES",
    32 * 1024 * 1024,
    crate::system::ZeroCeiling::Refused,
    "decimal byte count",
);

/// Per-request deadline (slowloris ceiling): `IPE_HTTP_REQUEST_TIMEOUT` seconds, default 30.
const REQUEST_TIMEOUT_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_HTTP_REQUEST_TIMEOUT",
    30,
    crate::system::ZeroCeiling::Refused,
    "decimal second count",
);

/// Global in-flight request cap: `IPE_HTTP_MAX_INFLIGHT`, default 1024.
const MAX_INFLIGHT_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_HTTP_MAX_INFLIGHT",
    1024,
    crate::system::ZeroCeiling::Refused,
    "decimal request count",
)
.at_most(tokio::sync::Semaphore::MAX_PERMITS as u64);

fn max_body() -> Result<usize, crate::system::EnvCeilingRefusal> {
    MAX_BODY_CEILING.read()
}

/// The ceilings `Server.listen` applies to its listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ListenCeilings {
    /// The per-request deadline, in seconds.
    request_timeout_secs: u64,
    /// The global in-flight request cap.
    max_inflight: usize,
}

/// Resolves every server ceiling once, before the listener binds.
///
/// The per-request and per-socket ceilings are re-read where they apply; this
/// preflight makes a malformed one refuse `Server.listen` instead of every
/// request.
fn listen_ceilings() -> Result<ListenCeilings, crate::system::EnvCeilingRefusal> {
    max_body()?;
    ws_ceilings()?;
    #[cfg(feature = "jwt")]
    crate::app_config::auth_ceilings()?;
    Ok(ListenCeilings {
        request_timeout_secs: REQUEST_TIMEOUT_CEILING.read()?,
        max_inflight: MAX_INFLIGHT_CEILING.read()?,
    })
}

/// Why a request is turned away before its handler runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestRejection {
    /// The body exceeds the request-body ceiling.
    PayloadTooLarge,
    /// The path or query is not a well-formed URL (a malformed escape, decoded
    /// bytes that are not UTF-8, an over-cap component or too many query
    /// pairs), or the headers have no one reading (a repeated singleton, a
    /// value outside visible ASCII).
    BadRequest,
    /// The request-body ceiling's environment value is malformed.
    Unavailable,
    /// The request reached a handler without the listener's URL parse.
    Unparsed,
    /// The router reached a handler whose pattern does not match the
    /// request's decoded path: the router and the pattern disagree.
    Unrouted,
}

impl RequestRejection {
    /// The status and fixed reason text answered for this rejection.
    ///
    /// The text never echoes the request, so a refusal reflects nothing back.
    pub(crate) const fn status_and_reason(self) -> (axum::http::StatusCode, &'static str) {
        match self {
            Self::PayloadTooLarge => (
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "Payload Too Large",
            ),
            Self::BadRequest => (axum::http::StatusCode::BAD_REQUEST, "Bad Request"),
            Self::Unavailable => (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
            ),
            Self::Unparsed | Self::Unrouted => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            ),
        }
    }
}

/// Decode the request's query string, refusing it whole on any defect.
fn parse_query(q: Option<&str>) -> Result<HashMap<String, String>, crate::encoding::QueryRefusal> {
    q.map_or_else(|| Ok(HashMap::new()), crate::encoding::decode_form_query)
}

/// The listener's parse of this request's URL, read from its extensions.
///
/// Only [`CanonicalUrl`] parses a request URL; every handler and gate behind
/// it reads that one parse, so no entry point decodes the URL a second way.
///
/// # Errors
///
/// `Unparsed` (a fixed 500) when the request carries no [`StrictUrl`]: it was
/// reached without the listener's parse, so it is refused rather than parsed
/// afresh.
pub(crate) const fn strict_url(parsed: Option<&StrictUrl>) -> Result<&StrictUrl, RequestRejection> {
    match parsed {
        Some(url) => Ok(url),
        None => Err(RequestRejection::Unparsed),
    }
}

/// Middleware refusing, with the fixed 500, a request that reaches the inner
/// service without the listener's [`StrictUrl`].
pub(crate) async fn refuse_unparsed_url(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match strict_url(req.extensions().get()) {
        Ok(_) => next.run(req).await,
        Err(rejection) => rejection.status_and_reason().into_response(),
    }
}

/// How a request spelled its path against the one canonical spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spelling {
    /// The request sent the canonical spelling byte for byte.
    Canonical,
    /// The request sent another spelling of the same decoded path.
    Respelled,
}

/// The listener's parse of one request URL and its headers, carried as a
/// request extension.
///
/// Only [`CanonicalUrl`] builds one, so a handler that finds none was reached
/// without the listener's parse and refuses rather than parse again. Its path
/// is the one the router it reaches sees: a mount re-bases it below its prefix
/// ([`MountTable`]).
#[derive(Clone)]
pub(crate) struct StrictUrl {
    #[cfg(feature = "web")]
    spelling: Spelling,
    path: crate::encoding::RequestPath,
    query: Arc<HashMap<String, String>>,
    headers: Arc<crate::http_header::RequestHeaders>,
}

impl StrictUrl {
    /// Whether the client sent the canonical spelling of its path.
    #[cfg(feature = "web")]
    pub(crate) const fn spelling(&self) -> Spelling {
        self.spelling
    }

    /// The decoded path segments.
    #[cfg(feature = "web")]
    pub(crate) const fn path(&self) -> &crate::encoding::DecodedPath {
        self.path.decoded()
    }

    /// The decoded path with its trailing slash.
    pub(crate) const fn request_path(&self) -> &crate::encoding::RequestPath {
        &self.path
    }

    /// The decoded query pairs.
    pub(crate) fn query(&self) -> &HashMap<String, String> {
        &self.query
    }

    /// The program-visible request headers.
    pub(crate) fn headers(&self) -> &crate::http_header::RequestHeaders {
        &self.headers
    }

    /// This parse with its path below `base`, or `None` when `base` is not a
    /// whole-segment prefix of it.
    fn below(&self, base: &crate::encoding::DecodedPath) -> Option<Self> {
        Some(Self {
            #[cfg(feature = "web")]
            spelling: self.spelling,
            path: self.path.below(base)?,
            query: Arc::clone(&self.query),
            headers: Arc::clone(&self.headers),
        })
    }
}

/// The static and Web mounts of one listener, longest prefix first.
///
/// No mount is a router insert: a request no handler route matches reaches
/// [`MountTable::serve`], which hands it to the mount whose prefix is the
/// longest whole-segment prefix of its decoded path. So a mount never
/// conflicts with a route, a prefix nested under another is served by its
/// longer mount, and a handler shadows a mount on every path it routes.
pub(crate) struct MountTable(Vec<(crate::encoding::MountBase, axum::Router)>);

impl MountTable {
    /// The table over `mounts`, whose prefixes are distinct
    /// ([`mount_conflict`]).
    pub(crate) fn new(mut mounts: Vec<(crate::encoding::MountBase, axum::Router)>) -> Self {
        mounts.sort_by_key(|(base, _)| std::cmp::Reverse(base.segments().count()));
        Self(mounts)
    }

    /// `app` with this table serving every request no route of `app` matches.
    pub(crate) fn below(self, app: axum::Router) -> axum::Router {
        if self.0.is_empty() {
            return app;
        }
        let table = Arc::new(self);
        app.fallback(move |req: axum::extract::Request| {
            let table = Arc::clone(&table);
            async move { table.serve(req).await }
        })
    }

    /// The mount that serves `url` and its parse below the mount's prefix.
    fn select(&self, url: &StrictUrl) -> Option<(&axum::Router, StrictUrl)> {
        self.0
            .iter()
            .find_map(|(base, router)| Some((router, url.below(base.to_decoded())?)))
    }

    /// Serve `request` by the mount [`MountTable::select`] picks, its URI path
    /// and its [`StrictUrl`] both re-based below the mount's prefix; 404 when
    /// no mount's prefix holds the path.
    async fn serve(&self, mut request: axum::extract::Request) -> axum::response::Response {
        use axum::response::IntoResponse;
        use tower::ServiceExt;
        let selected = match strict_url(request.extensions().get()) {
            Ok(url) => self
                .select(url)
                .map(|(router, below)| (router.clone(), below)),
            Err(rejection) => return rejection.status_and_reason().into_response(),
        };
        let Some((router, below)) = selected else {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        };
        let respelled = below
            .request_path()
            .canonical()
            .map_err(|_| RequestRejection::BadRequest)
            .and_then(|path| respell_path(&mut request, &path));
        if let Err(rejection) = respelled {
            return rejection.status_and_reason().into_response();
        }
        request.extensions_mut().insert(below);
        match router.oneshot(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }
}

/// The outermost URL service of every app listener: one strict parse, then
/// the canonical respelling of the path, before any router sees the request.
///
/// A malformed path or query is answered with the fixed 400 before routing, so
/// an unrouted path and the fallback are refused alike; the 400 carries the
/// response security headers every served response carries. Every other request
/// reaches the inner service with its path respelled by
/// [`crate::encoding::canonical_path`] (the query bytes kept) and a
/// [`StrictUrl`] extension, so matchit, every nest prefix and every file
/// service compare canonical text only and two spellings of one decoded path
/// can never route apart. It wraps the router as a service, never through
/// `Router::layer` (which runs after routing).
#[derive(Clone)]
pub(crate) struct CanonicalUrl<S> {
    inner: S,
}

impl<S> CanonicalUrl<S> {
    /// The canonical-URL service in front of `inner`.
    pub(crate) const fn new(inner: S) -> Self {
        Self { inner }
    }
}

/// The future of [`CanonicalUrl`]: the refusal, or the inner call.
type CanonicalFuture<F> = futures_util::future::Either<
    std::future::Ready<Result<axum::response::Response, std::convert::Infallible>>,
    F,
>;

impl<S> tower::Service<axum::extract::Request> for CanonicalUrl<S>
where
    S: tower::Service<
            axum::extract::Request,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        >,
{
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = CanonicalFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: axum::extract::Request) -> Self::Future {
        use axum::response::IntoResponse;
        match canonicalise(&mut request) {
            Ok(()) => futures_util::future::Either::Right(self.inner.call(request)),
            Err(rejection) => {
                futures_util::future::Either::Left(std::future::ready(Ok(with_security_headers(
                    rejection.status_and_reason().into_response(),
                    response_security_headers(),
                ))))
            }
        }
    }
}

/// The layer that counts each admitted request as shutdown work.
///
/// It wraps the router inside the Host admission, so a refused request holds
/// nothing.
#[derive(Clone)]
struct WorkLayer {
    count: shutdown::WorkCount,
}

impl<S> tower::Layer<S> for WorkLayer {
    type Service = WorkService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WorkService {
            inner,
            count: self.count.clone(),
        }
    }
}

/// Each request holds one [`shutdown::WorkGuard`] until its response head
/// exists; a request past the work ceiling, or one still running when the
/// shutdown closes, is answered 503 with `Connection: close`.
///
/// The cancel arm is polled first, so a request that arrives once the phase
/// is closing never reaches its handler.
#[derive(Clone)]
struct WorkService<S> {
    inner: S,
    count: shutdown::WorkCount,
}

impl<S> tower::Service<axum::extract::Request> for WorkService<S>
where
    S: tower::Service<
            axum::extract::Request,
            Response = axum::response::Response,
            Error = std::convert::Infallible,
        >,
    S::Future: Send + 'static,
{
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future =
        futures_util::future::BoxFuture<'static, Result<Self::Response, std::convert::Infallible>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: axum::extract::Request) -> Self::Future {
        let Ok(mut guard) = self.count.guard() else {
            return Box::pin(std::future::ready(Ok(work_cancelled())));
        };
        let handled = self.inner.call(request);
        Box::pin(async move {
            tokio::select! {
                biased;
                () = guard.cancelled() => Ok(work_cancelled()),
                response = handled => response,
            }
        })
    }
}

/// The 503 a request the shutdown cancels, or the work ceiling refuses, reads.
fn work_cancelled() -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut resp = with_security_headers(
        RequestRejection::Unavailable
            .status_and_reason()
            .into_response(),
        response_security_headers(),
    );
    resp.headers_mut().insert(
        axum::http::header::CONNECTION,
        axum::http::HeaderValue::from_static("close"),
    );
    resp
}

/// Parse `request`'s URL and headers once, respell its path canonically and
/// record the parse as its [`StrictUrl`] extension.
///
/// # Errors
///
/// `BadRequest` for a malformed path or query, a path whose canonical
/// spelling exceeds the URL component ceiling, or headers with no one reading
/// ([`crate::http_header::RequestHeaders::parse`]).
fn canonicalise(request: &mut axum::extract::Request) -> Result<(), RequestRejection> {
    let headers = crate::http_header::RequestHeaders::parse(request.headers())
        .map_err(|_| RequestRejection::BadRequest)?;
    let uri = request.uri();
    let path = crate::encoding::RequestPath::parse(uri.path())
        .map_err(|_| RequestRejection::BadRequest)?;
    let query = parse_query(uri.query()).map_err(|_| RequestRejection::BadRequest)?;
    let canonical = path.canonical().map_err(|_| RequestRejection::BadRequest)?;
    let spelling = if canonical.as_str() == uri.path() {
        Spelling::Canonical
    } else {
        Spelling::Respelled
    };
    if spelling == Spelling::Respelled {
        respell_path(request, &canonical)?;
    }
    request.extensions_mut().insert(StrictUrl {
        #[cfg(feature = "web")]
        spelling,
        path,
        query: Arc::new(query),
        headers: Arc::new(headers),
    });
    Ok(())
}

/// Replace `request`'s URI path with `path`, keeping its query bytes.
///
/// # Errors
///
/// `BadRequest` when the respelled target is not a URI.
fn respell_path(
    request: &mut axum::extract::Request,
    path: &crate::encoding::CanonicalPath,
) -> Result<(), RequestRejection> {
    let uri = request.uri();
    let target = uri.query().map_or_else(
        || path.as_str().to_owned(),
        |query| format!("{}?{query}", path.as_str()),
    );
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(
        axum::http::uri::PathAndQuery::try_from(target)
            .map_err(|_| RequestRejection::BadRequest)?,
    );
    *request.uri_mut() =
        axum::http::Uri::from_parts(parts).map_err(|_| RequestRejection::BadRequest)?;
    Ok(())
}

/// `router` behind the listener's [`CanonicalUrl`], still an `axum::Router`.
///
/// A test drives a router the way a listener serves it: an outer router with
/// no route hands every request, untouched, to its fallback service.
#[cfg(test)]
pub(crate) fn behind_listener(router: axum::Router) -> axum::Router {
    axum::Router::new().fallback_service(CanonicalUrl::new(router))
}

/// What a static-file mount may serve for one request path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum StaticRequest {
    /// The mount's own directory (no segment).
    Root,
    /// A path beneath the directory whose every segment is a plain name.
    File(crate::path_core::RelPath),
}

/// Why a static-file request path may not reach the filesystem.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum StaticRefusal {
    /// The strict core refused the path text itself.
    #[cfg(any(test, feature = "web"))]
    Malformed(crate::encoding::DecodeRefusal),
    /// A decoded segment is not a plain name under the serving regime.
    Segment(crate::path_core::RelPathRefusal),
    /// The served directory is not UTF-8 text, so no join beneath it is judged.
    RootNotText,
    /// The checked join of the parsed path beneath the directory refused.
    Join(crate::path::PathRefusal),
}

/// Parse a static-file request path under the serving `regime`, or say why it
/// may not reach the filesystem beneath `root`.
///
/// The path is decoded once by the strict core (`DecodedPath::parse`; a
/// malformed one was already answered 400 by [`CanonicalUrl`]), then
/// parsed into a `RelPath`, so a segment that climbs, re-anchors, names a
/// device or a stream, or aliases another entry under the regime is refused
/// before any join. An empty segment (`/a//b`) names no entry and is refused
/// too. The join itself ([`crate::path::join_rel`]) then re-checks the joined
/// text independently; its result is discarded here.
///
/// # Errors
///
/// The [`StaticRefusal`] of the first boundary that refused the path.
#[cfg(any(test, feature = "web"))]
pub(crate) fn static_request(
    uri_path: &str,
    root: &std::path::Path,
    regime: crate::path_core::Regime,
) -> Result<StaticRequest, StaticRefusal> {
    let decoded =
        crate::encoding::DecodedPath::parse(uri_path).map_err(StaticRefusal::Malformed)?;
    static_request_of(&decoded, root, regime)
}

/// `static_request` over a path already decoded.
///
/// # Errors
///
/// The [`StaticRefusal`] of the first boundary that refused the path.
fn static_request_of(
    decoded: &crate::encoding::DecodedPath,
    root: &std::path::Path,
    regime: crate::path_core::Regime,
) -> Result<StaticRequest, StaticRefusal> {
    if decoded.is_root() {
        return Ok(StaticRequest::Root);
    }
    let rel = crate::path_core::RelPath::from_segments(
        decoded.segments().iter().map(String::as_str),
        regime,
    )
    .map_err(StaticRefusal::Segment)?;
    let root = root.to_str().ok_or(StaticRefusal::RootNotText)?;
    crate::path::join_rel(root, &rel).map_err(StaticRefusal::Join)?;
    Ok(StaticRequest::File(rel))
}

/// Whether the static gate lets `req` reach the file service beneath `root`.
///
/// The gate judges the listener's parse ([`StrictUrl`]), never a decode of
/// its own, and admits only when the URI text the file service will decode
/// names that same path: a request without the parse, a path
/// [`static_request_of`] refuses, or a URI that reads as another path is
/// refused.
fn static_admits(
    req: &axum::extract::Request,
    root: &std::path::Path,
    regime: crate::path_core::Regime,
) -> bool {
    let Ok(url) = strict_url(req.extensions().get()) else {
        return false;
    };
    let parsed = url.request_path().decoded();
    static_request_of(parsed, root, regime).is_ok()
        && crate::encoding::DecodedPath::parse(req.uri().path()).as_ref() == Ok(parsed)
}

/// A static file service behind the strict URL gate and the static path gate.
///
/// `ServeDir` percent-decodes the path itself; the gates make that decode run
/// only on a path the listener's parse holds and [`static_request_of`]
/// admits under the host regime.
pub(crate) fn strict_serve_dir(
    dir: std::path::PathBuf,
) -> impl tower::Service<
    axum::extract::Request,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
    Future: Send + 'static,
> + Clone
+ Send
+ 'static {
    strict_serve_dir_with(dir, crate::path_core::HOST)
}

/// [`strict_serve_dir`] under an explicit `regime`, so any host proves the
/// Windows refusals.
///
/// A request path `static_request` refuses is answered a bare 404 that never
/// echoes the path, whether or not the entry exists. Every answer carries the
/// response security headers.
fn strict_serve_dir_with(
    dir: std::path::PathBuf,
    regime: crate::path_core::Regime,
) -> impl tower::Service<
    axum::extract::Request,
    Response = axum::response::Response,
    Error = std::convert::Infallible,
    Future: Send + 'static,
> + Clone
+ Send
+ 'static {
    use axum::response::IntoResponse;
    let root = dir.clone();
    let static_gate = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let admitted = static_admits(&req, &root, regime);
            async move {
                if admitted {
                    next.run(req).await
                } else {
                    axum::http::StatusCode::NOT_FOUND.into_response()
                }
            }
        },
    );
    let security_gate = axum::middleware::from_fn(
        |req: axum::extract::Request, next: axum::middleware::Next| async move {
            with_security_headers(next.run(req).await, response_security_headers())
        },
    );
    tower::Layer::layer(
        &security_gate,
        tower::Layer::layer(
            &axum::middleware::from_fn(refuse_unparsed_url),
            tower::Layer::layer(&static_gate, tower_http::services::ServeDir::new(dir)),
        ),
    )
}

/// `resp` with each `security` header it does not already carry.
///
/// A refused set, a header with no representation, or a full header map
/// answers a bare `500`: no response ships without its security headers.
pub(crate) fn with_security_headers(
    mut resp: axum::response::Response,
    security: Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(security) = security else {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    for (name, value) in security {
        let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            axum::http::HeaderValue::from_str(&value),
        ) else {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
        if !resp.headers().contains_key(&name)
            && resp.headers_mut().try_insert(name, value).is_err()
        {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    resp
}

/// Add the decoded cookies of one request's jar to `out`; the first value of a name wins.
#[cfg(test)]
fn parse_cookies<'a, I>(jar: I, out: &mut HashMap<String, String>)
where
    I: IntoIterator<Item = &'a [u8]>,
    I::IntoIter: 'a,
{
    for (name, value) in request_cookies(jar) {
        out.entry(name).or_insert(value);
    }
}

/// The decoded `(name, value)` pairs of every `Cookie` header in `headers`, in order.
///
/// Read from the raw header bytes through [`request_cookies`], so a pair with
/// a byte outside visible ASCII drops only itself, never the other cookies.
pub fn request_cookie_jar(
    headers: &axum::http::HeaderMap,
) -> impl Iterator<Item = (String, String)> + '_ {
    request_cookies(
        headers
            .get_all(axum::http::header::COOKIE)
            .iter()
            .map(axum::http::HeaderValue::as_bytes),
    )
}

/// The decoded value of the request cookie `name`, read from every `Cookie` header.
///
/// The first value of `name` wins, as in `parse_cookies`.
#[must_use]
pub fn request_cookie(headers: &axum::http::HeaderMap, name: &CookieName) -> Option<String> {
    request_cookie_jar(headers).find_map(|(k, v)| (k == name.text()).then_some(v))
}

/// The client address a handler reads as `remoteAddr`.
///
/// The TCP peer by default. Only with `trust_proxy` (the operator declares one
/// trusted proxy in front, `IPE_TRUSTED_PROXY`) does a forwarding header
/// decide: the RIGHTMOST `X-Forwarded-For` entry, the one that proxy appended
/// (every entry left of it is client-supplied), or else `X-Real-Ip`. A
/// forwarded value that is not an IP address falls back to the peer, never
/// to its raw text.
fn remote_address(
    headers: &crate::http_header::RequestHeaders,
    peer: Option<std::net::IpAddr>,
    trust_proxy: bool,
) -> String {
    let forwarded = if trust_proxy {
        headers.get("X-Forwarded-For").map_or_else(
            || {
                headers
                    .get("X-Real-Ip")
                    .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
            },
            |list| {
                list.rsplit(',')
                    .next()
                    .and_then(|entry| entry.trim().parse::<std::net::IpAddr>().ok())
            },
        )
    } else {
        None
    };
    forwarded
        .or(peer)
        .map(|ip| ip.to_string())
        .unwrap_or_default()
}

/// Build the Ipê `ServerRequest` from the axum request.
///
/// Its path parameters are the decoded segments `pattern` captures from the
/// listener's parse, never the router's own decode.
///
/// Returns the `RequestRejection` when the request must be turned away before
/// the handler runs: a request without the listener's parse is `Unparsed`, one
/// `pattern` does not match is `Unrouted`, an oversize body is
/// `PayloadTooLarge`. Rejecting here ensures a handler never sees a lossily
/// decoded URL, an empty parameter table or a silently-truncated body.
async fn build_request(
    req: axum::extract::Request,
    pattern: &crate::encoding::ServerPattern,
) -> Result<(ServerRequest, Option<axum::extract::ws::WebSocketUpgrade>), RequestRejection> {
    use axum::extract::FromRequestParts;
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    // The listener respelled the path canonically: this is the encoder's text.
    let path = uri.path().to_string();
    let strict = strict_url(req.extensions().get())?;
    let query = strict.query().clone();
    // The router chose this handler by the canonical spelling; the pattern
    // re-matches the decoded segments. A disagreement is a broken invariant,
    // refused, never served an empty table.
    let captured = pattern
        .captures(strict.request_path())
        .ok_or(RequestRejection::Unrouted)?;
    let params: HashMap<String, String> = pattern
        .pattern()
        .param_names()
        .map(str::to_owned)
        .zip(captured.into_segments())
        .collect();
    // The listener's one header fold, keyed by canonical MIME casing, so
    // `server_header` (which canonicalises its lookup key) matches any caller
    // casing and the dict agrees with `Ipe.Web`'s.
    let headers = strict.headers().as_dict().clone();
    let trust_proxy = crate::system::read_env_var("IPE_TRUSTED_PROXY")
        .map(|v| !v.is_empty() && v != "0" && v != "false")
        .unwrap_or(false);
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let remote_addr = remote_address(strict.headers(), peer, trust_proxy);
    let mut cookies = HashMap::new();
    // Read from the raw bytes of every `Cookie` header, outside the header
    // fold, so one pair with a non-ASCII byte drops only itself. The first
    // value of a name wins.
    for (name, value) in request_cookie_jar(req.headers()) {
        cookies.entry(name).or_insert(value);
    }
    let (mut parts, body) = req.into_parts();
    // Extract the WebSocket upgrader if this is an upgrade request
    // (succeeds only when the Connection/Upgrade/Sec-WebSocket-* headers are
    // present). Stashed via task-local so server_web_socket_upgrade can reach it.
    let upgrader = axum::extract::ws::WebSocketUpgrade::from_request_parts(&mut parts, &())
        .await
        .ok();
    // A malformed ceiling refuses the request rather than widening the cap.
    let Ok(cap) = max_body() else {
        return Err(RequestRejection::Unavailable);
    };
    // Reject an oversize body with 413 instead of silently truncating to "".
    // Pre-check Content-Length when declared (deterministic for non-chunked
    // requests); to_bytes still enforces the cap for chunked bodies.
    if let Some(declared) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        && declared > cap
    {
        return Err(RequestRejection::PayloadTooLarge);
    }
    let body = match axum::body::to_bytes(body, cap).await {
        #[allow(clippy::disallowed_methods)]
        // a request body reaches the handler as `String` text, not a URL component
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        // to_bytes-with-limit fails almost exclusively on cap-exceeded; a
        // transport read error means the client is already gone so the status
        // is moot. Either way never hand the handler a silently-truncated body.
        Err(_) => return Err(RequestRejection::PayloadTooLarge),
    };
    Ok((
        ServerRequest {
            method,
            path,
            body,
            headers,
            params,
            query,
            cookies,
            remoteAddr: remote_addr,
        },
        upgrader,
    ))
}

/// The response `r` sends, claiming its stream from `streams`, the table of
/// the request `r` answers.
fn to_axum_response(r: ServerResponse, streams: RequestStreams) -> axum::response::Response {
    to_axum_response_with(r, streams, response_security_headers())
}

/// The security headers of a handler response or a static file: the
/// [`crate::csp::Guarded::Response`] policy.
fn response_security_headers()
-> Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal> {
    crate::telemetry::security_headers(&crate::csp::Guarded::Response)
}

/// [`to_axum_response`] over the outcome of reading the security headers.
fn to_axum_response_with(
    r: ServerResponse,
    streams: RequestStreams,
    security: Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // A streaming response carries the sentinel body `stream` registered in
    // this request's table. Claiming it takes its handler, which runs only
    // once the head is built.
    let pending = match claim_streaming_sentinel(&r.body, streams) {
        ServerStreamClaim::Buffered => None,
        ServerStreamClaim::Stream(pending) => Some(pending),
        // Sentinel text this request cannot serve: sending it as a buffered
        // body would put stream tickets on the wire.
        ServerStreamClaim::Refused => {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let delivery = if pending.is_some() {
        ServerDelivery::Streamed
    } else {
        ServerDelivery::Buffered
    };
    let Ok(head) = assemble_response_head(&r, delivery, security) else {
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    if let Some(pending) = pending {
        return pending.serve(head);
    }
    // Dev-only "🔍 Console" banner injection for every text/html buffered body.
    // Prefix test matches `strings.HasPrefix(ct, "text/html")` exactly:
    // case-sensitive, no trimming.
    let banner = if head.is_html() {
        crate::telemetry::dev_console_banner("")
    } else {
        String::new()
    };
    // An empty banner (production, or banner-off env, or a non-html response)
    // leaves the body unchanged, so move it rather than copy it through the
    // injector's no-op branch.
    let body = if banner.is_empty() {
        r.body
    } else {
        crate::telemetry::inject_dev_banner(&r.body, &banner)
    };
    head.into_response(axum::body::Body::from(body))
}

/// The router entry serving `h` for `method` at `pattern`.
fn method_router(
    method: EndpointMethod,
    pattern: crate::encoding::ServerPattern,
    h: ErasedHandler,
) -> axum::routing::MethodRouter {
    use axum::response::IntoResponse;
    let pattern = Arc::new(pattern);
    let svc = move |req: axum::extract::Request| {
        let h = h.clone();
        let pattern = Arc::clone(&pattern);
        async move {
            let (ipe_req, upgrader) = match build_request(req, &pattern).await {
                Ok(v) => v,
                Err(rejection) => return rejection.status_and_reason().into_response(),
            };
            // Run the handler with the WS upgrader + a response slot in scope.
            // If the handler called server_web_socket_upgrade, it stashed the
            // real 101 response in WS_RESPONSE — prefer it over the sentinel.
            WS_UPGRADER
                .scope(std::cell::Cell::new(upgrader), async move {
                    WS_RESPONSE
                        .scope(std::cell::Cell::new(None), async move {
                            let (result, streams) = dispatch(&h, ipe_req).await;
                            // An upgraded socket answers the request; the
                            // streams it registered drop unclaimed.
                            if let Some(ws_resp) = WS_RESPONSE.with(|c| c.take()) {
                                return ws_resp;
                            }
                            match result {
                                Ok(resp) => to_axum_response(resp, streams),
                                Err(_) => (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    "Internal Server Error",
                                )
                                    .into_response(),
                            }
                        })
                        .await
                })
                .await
        }
    };
    match method.filter() {
        Some(filter) => axum::routing::on(filter, svc),
        None => axum::routing::any(svc),
    }
}

use crate::encoding::EndpointMethod;

impl EndpointMethod {
    /// The router's filter for this method; `None` for `Any`.
    const fn filter(self) -> Option<axum::routing::MethodFilter> {
        use axum::routing::MethodFilter as F;
        match self {
            Self::Connect => Some(F::CONNECT),
            Self::Delete => Some(F::DELETE),
            Self::Get => Some(F::GET),
            Self::Head => Some(F::HEAD),
            Self::Options => Some(F::OPTIONS),
            Self::Patch => Some(F::PATCH),
            Self::Post => Some(F::POST),
            Self::Put => Some(F::PUT),
            Self::Trace => Some(F::TRACE),
            Self::Any => None,
        }
    }
}

/// What one parsed route serves.
enum ParsedTarget {
    /// A handler for the requests of one method set whose path its pattern
    /// matches.
    Handler(
        EndpointMethod,
        crate::encoding::ServerPattern,
        ErasedHandler,
    ),
    /// A static-file directory served below a prefix.
    Static(crate::encoding::MountBase, String),
    /// An embedded Web app served below a prefix.
    #[cfg(feature = "web")]
    MountWeb(crate::encoding::MountBase, MountCell),
}

impl ParsedTarget {
    /// The prefix a mount serves below, or `None` for a handler.
    const fn mount_base(&self) -> Option<&crate::encoding::MountBase> {
        match self {
            Self::Handler(..) => None,
            Self::Static(base, _) => Some(base),
            #[cfg(feature = "web")]
            Self::MountWeb(base, _) => Some(base),
        }
    }
}

/// One `Ipe.Server` route parsed at listen, before any router insert.
struct ParsedRoute {
    /// The method as the program named it, for messages.
    method: String,
    /// The path as the program wrote it, for messages.
    path: String,
    target: ParsedTarget,
}

/// Why one route was refused at listen.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RouteCause {
    /// The path is not an `Ipe.Server` route pattern.
    Pattern(crate::encoding::ServerPatternRefusal),
    /// A mount's prefix is not a mount base.
    Prefix(crate::encoding::MountBaseRefusal),
    /// A handler's method is no HTTP method.
    Method,
}

impl RouteCause {
    /// Whether a declared ceiling refused the route: a larger bound would
    /// admit the same text.
    const fn is_ceiling(&self) -> bool {
        use crate::encoding::{
            DecodeRefusal as D, EncodeRefusal as E, MountBaseRefusal as M,
            RouteSegmentRefusal as S, ServerPatternRefusal as P,
        };
        match self {
            Self::Pattern(
                P::TooManyParams { .. }
                | P::Render(E::TooLong { .. })
                | P::Segment(S::Decode(D::TooLong { .. })),
            )
            | Self::Prefix(M::TooLong { .. }) => true,
            Self::Pattern(
                P::NotAbsolute
                | P::Segment(
                    S::Decode(D::MalformedEscape { .. } | D::InvalidUtf8 { .. })
                    | S::ParamName(_)
                    | S::CatchAll
                    | S::MidSegmentSigil { .. },
                )
                | P::Render(E::Empty | E::Dot),
            )
            | Self::Prefix(
                M::NoLeadingSlash
                | M::TrailingSlash
                | M::EmptySegment
                | M::DotSegment
                | M::Reserved { .. },
            )
            | Self::Method => false,
        }
    }
}

/// A route refused at listen, named by its method and path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EndpointRefusal {
    /// The route as [`quoted_endpoint`] quotes it.
    endpoint: RefusedText,
    cause: RouteCause,
}

/// How many characters of a refused path a listen error quotes.
const PATH_EXCERPT_CHARS: usize = 64;

/// How many characters of a refused method a listen error quotes: every HTTP
/// method the server serves is shorter.
const METHOD_EXCERPT_CHARS: usize = 16;

/// The first `max` characters of `text`, ending in `…` when it is longer.
fn excerpt(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let mut head: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        head.push('…');
    }
    head
}

/// `METHOD path` for a listen error: log hazards escaped, the method cut to
/// [`METHOD_EXCERPT_CHARS`] and the path to [`PATH_EXCERPT_CHARS`]
/// characters.
fn quoted_endpoint(method: &str, path: &str) -> RefusedText {
    RefusedText::new(&format!(
        "{} {}",
        excerpt(method, METHOD_EXCERPT_CHARS),
        excerpt(path, PATH_EXCERPT_CHARS)
    ))
}

impl std::fmt::Display for EndpointRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let endpoint = &self.endpoint;
        match &self.cause {
            RouteCause::Pattern(refusal) => write!(
                f,
                "Server.listen: endpoint `{endpoint}` is not a well-formed route path: {refusal}"
            ),
            RouteCause::Prefix(refusal) => write!(
                f,
                "Server.listen: mount `{endpoint}` is not a well-formed mount prefix: {refusal}"
            ),
            RouteCause::Method => write!(
                f,
                "Server.listen: endpoint `{endpoint}` names no HTTP method; use GET, POST, PUT, \
                 DELETE, PATCH, HEAD, OPTIONS, TRACE, CONNECT or ANY"
            ),
        }
    }
}

/// Why `Server.listen` refused its route set before it bound a port.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ServerStartRefusal {
    /// A route's path, mount prefix or method does not parse.
    Route(EndpointRefusal),
    /// Two handlers claim one route shape with an overlapping method.
    Overlap {
        earlier: RefusedText,
        later: RefusedText,
    },
    /// Two mounts serve one prefix.
    SharedPrefix {
        earlier: RefusedText,
        later: RefusedText,
    },
    /// The router refused an insert every listen check admitted.
    RouterRejected { endpoint: RefusedText },
}

impl std::fmt::Display for ServerStartRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Route(refusal) => write!(f, "{refusal}"),
            Self::Overlap { earlier, later } => write!(
                f,
                "Server.listen: endpoint `{earlier}` conflicts with `{later}` — two handlers may \
                 not claim the same path with an overlapping method; give each endpoint a \
                 distinct path or method"
            ),
            Self::SharedPrefix { earlier, later } => write!(
                f,
                "Server.listen: mount `{earlier}` and mount `{later}` serve one prefix — two \
                 mounts may not share a prefix; give each mount its own prefix (a prefix nested \
                 under another is served by the longer one)"
            ),
            Self::RouterRejected { endpoint } => write!(
                f,
                "Server.listen: the router refused to register endpoint `{endpoint}` beside the \
                 routes before it, although every listen check admitted the route set"
            ),
        }
    }
}

impl ServerStartRefusal {
    /// The error `Server.listen` fails with, of the kind this refusal is.
    fn into_ipe_error(self) -> IpeError {
        let message = self.to_string();
        match self {
            Self::Route(refusal) if refusal.cause.is_ceiling() => IpeError::limit_exceeded(message),
            Self::Route(_) => IpeError::invalid_input(message),
            Self::Overlap { .. } | Self::SharedPrefix { .. } | Self::RouterRejected { .. } => {
                IpeError::conflict(message)
            }
        }
    }
}

/// Parse every route once, in declaration order: a handler's path into a
/// [`crate::encoding::ServerPattern`] and its method into an
/// [`EndpointMethod`], a mount's prefix into a
/// [`crate::encoding::MountBase`].
///
/// # Errors
///
/// The refusal of the first route whose path or method does not parse.
fn parse_routes(routes: Vec<ServerRoute>) -> Result<Vec<ParsedRoute>, EndpointRefusal> {
    routes
        .into_iter()
        .map(|r| {
            let refuse = |cause| EndpointRefusal {
                endpoint: quoted_endpoint(&r.method.to_uppercase(), &r.path),
                cause,
            };
            let pattern = || {
                crate::encoding::ServerPattern::parse(&r.path)
                    .map_err(|refusal| refuse(RouteCause::Pattern(refusal)))
            };
            let prefix = || {
                crate::encoding::MountBase::parse(&r.path)
                    .map_err(|refusal| refuse(RouteCause::Prefix(refusal)))
            };
            let target = match r.target {
                RouteTarget::Handler(h) => {
                    let pattern = pattern()?;
                    let method = EndpointMethod::parse(&r.method)
                        .ok_or_else(|| refuse(RouteCause::Method))?;
                    ParsedTarget::Handler(method, pattern, h)
                }
                RouteTarget::Static(dir) => ParsedTarget::Static(prefix()?, dir),
                #[cfg(feature = "web")]
                RouteTarget::MountWeb(cell) => ParsedTarget::MountWeb(prefix()?, cell),
            };
            Ok(ParsedRoute {
                method: r.method,
                path: r.path,
                target,
            })
        })
        .collect()
}

impl ParsedRoute {
    /// This route as a listen error quotes it.
    fn endpoint(&self) -> RefusedText {
        quoted_endpoint(&self.method.to_uppercase(), &self.path)
    }
}

/// The first two handlers that claim one route with an overlapping method.
///
/// The router keys a handler by its pattern's router spelling, which two
/// patterns share exactly when they have one shape
/// ([`crate::encoding::ServerPattern::router_path`]); handlers of one
/// spelling merge into one route, and only an overlapping method makes that
/// merge a conflict. So this check refuses exactly the handler sets the
/// router could not register, before any insert.
fn endpoint_conflict(routes: &[ParsedRoute]) -> Option<ServerStartRefusal> {
    let mut seen: HashMap<&str, Vec<(EndpointMethod, &ParsedRoute)>> = HashMap::new();
    for route in routes {
        let ParsedTarget::Handler(method, pattern, _) = &route.target else {
            continue;
        };
        let method = *method;
        let claims = seen.entry(pattern.router_path()).or_default();
        if let Some((_, earlier)) = claims.iter().find(|(m, _)| m.overlaps(method)) {
            return Some(ServerStartRefusal::Overlap {
                earlier: earlier.endpoint(),
                later: route.endpoint(),
            });
        }
        claims.push((method, route));
    }
    None
}

/// The first two mounts that serve one prefix.
///
/// Mounts are matched by longest prefix ([`MountTable`]), which picks one
/// mount for every path only when no two prefixes are equal.
fn mount_conflict(routes: &[ParsedRoute]) -> Option<ServerStartRefusal> {
    let mut seen: HashMap<&crate::encoding::MountBase, &ParsedRoute> = HashMap::new();
    for route in routes {
        let Some(base) = route.target.mount_base() else {
            continue;
        };
        if let Some(earlier) = seen.insert(base, route) {
            return Some(ServerStartRefusal::SharedPrefix {
                earlier: earlier.endpoint(),
                later: route.endpoint(),
            });
        }
    }
    None
}

// The router reports a refused insert only by panicking, and a panicking
// handler is answered 500 by `CatchPanicLayer`: both rest on catching an
// unwind.
#[cfg(panic = "abort")]
compile_error!(
    "`server` catches router-insert and handler panics to answer them as typed refusals; a \
     `panic = \"abort\"` build cannot catch them"
);

/// Register `mr` at the router spelling `path`.
///
/// The listen checks refuse, before any insert, every route set the router
/// could not register; this is the backstop behind them. The router reports a
/// refused insert only by panicking, so the panic is caught and answered as
/// [`ServerStartRefusal::RouterRejected`] naming `endpoint`, never as a
/// refusal whose cause it may not be.
///
/// # Errors
///
/// `RouterRejected` when the router panics on the insert.
fn insert_endpoint(
    app: axum::Router,
    path: &str,
    mr: axum::routing::MethodRouter,
    endpoint: RefusedText,
) -> Result<axum::Router, ServerStartRefusal> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || app.route(path, mr)))
        .map_err(|_| ServerStartRefusal::RouterRejected { endpoint })
}

/// An app listener's [`ListenHost`](crate::app_config::ListenHost) whose
/// listen scope is already recorded for the process.
///
/// Built only by [`RecordedHost::record`] and the one input
/// [`bind_app_listener`] takes, so no app listener binds an address whose
/// scope the console gates have not seen.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RecordedHost(crate::app_config::ListenHost);

impl RecordedHost {
    /// Record `host`'s listen scope for the process, then carry it to the bind.
    pub(crate) fn record(host: crate::app_config::ListenHost) -> Self {
        crate::telemetry::record_bind(host.ip());
        Self(host)
    }

    /// The socket address this host binds on `port`.
    pub(crate) const fn addr(self, port: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.0.ip(), port)
    }
}

pub(crate) mod shutdown;

/// A bound app listener and the Host admission every request on it is judged
/// by.
///
/// Built only by [`bind_app_listener`] and consumed only by [`serve_app`], so
/// no app listener's socket can be served without its admission.
#[derive(Debug)]
pub(crate) struct AppListener {
    listener: tokio::net::TcpListener,
    admission: crate::inbound_authority::HostAdmission,
    tag: &'static str,
}

/// Why an app listener does not bind.
#[derive(Debug)]
pub(crate) enum AppBindError {
    /// The declared host list is refused; no socket was opened.
    Admission(crate::env_grammar::EnvRefusal),
    /// The socket's own bind error.
    Bind(std::io::Error),
}

/// The DNS names every app listener of this process admits, judged once.
///
/// Fixed by the first call, which [`crate::env_registry::startup_check`] makes,
/// so a later environment write cannot widen a running app's admission.
///
/// # Errors
///
/// The refusal of a malformed `IPE_HTTP_ALLOWED_HOSTS`, naming the variable
/// and never the value.
pub(crate) fn declared_names()
-> Result<&'static crate::inbound_authority::DeclaredNames, &'static crate::env_grammar::EnvRefusal>
{
    type Judged = Result<crate::inbound_authority::DeclaredNames, crate::env_grammar::EnvRefusal>;
    static NAMES: std::sync::OnceLock<Judged> = std::sync::OnceLock::new();
    NAMES
        .get_or_init(|| crate::env_registry::listen::ALLOWED_HOSTS.read())
        .as_ref()
}

/// Fixes [`declared_names`] for the process.
pub(crate) fn fix_declared_names() {
    let _ = declared_names();
}

/// Bind an app listener on `host` and `port`, then log where it listens, which
/// hosts it admits and, for an exposed host, who exposed it.
///
/// The one app bind site: `Server.listen` and `serve_web` both bind through
/// it, so neither keeps a `TcpListener::bind` of its own, and neither admits a
/// DNS name `IPE_HTTP_ALLOWED_HOSTS` does not declare.
///
/// # Errors
///
/// [`AppBindError::Admission`] for a refused host list, before any socket
/// opens; [`AppBindError::Bind`] with the bind's own error, for the caller to
/// word.
pub(crate) async fn bind_app_listener(
    tag: &'static str,
    host: RecordedHost,
    port: u16,
) -> Result<AppListener, AppBindError> {
    let names = declared_names().map_err(|refusal| AppBindError::Admission(refusal.clone()))?;
    let addr = host.addr(port);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(AppBindError::Bind)?;
    let admission = crate::inbound_authority::HostAdmission::new(names.clone());
    for line in startup_lines(addr, host.0, admission.names()) {
        crate::system::emit_runtime_log(tag, &line);
    }
    Ok(AppListener {
        listener,
        admission,
        tag,
    })
}

/// Serve `router` on `app`, judging every request's target authority against
/// the listener's Host admission before routing, until the armed shutdown
/// owner drains it; then close every owned pool.
///
/// The one app serve site. The admission wraps the router as a service, never
/// through `Router::layer` (which runs after routing), so an unrouted path and
/// the fallback are refused alike and a refused request reaches no handler,
/// session or concurrency permit.
///
/// Every admitted request is counted as shutdown work until its response head
/// exists.
///
/// Its only success is [`shutdown::Stopped`]: after the first signal the
/// in-flight requests, the counted work and the long-lived tasks get what is
/// left of the grace, and every other serve site sharing the owner drains too.
/// Then the work still running is cancelled (a request reads 503), the
/// exporters flush, and every owned pool closes under its deadline. A signal
/// that arrived before the serve skips accepting altogether.
///
/// Only a signalled stop tears down: a serve that ends before any signal
/// returns at once and leaves the shared owner serving.
///
/// # Errors
///
/// The serve loop's own error, for the caller to word.
#[allow(clippy::disallowed_methods)] // the one app serve site; Host admission wraps the router
pub(crate) async fn serve_app(
    app: AppListener,
    router: axum::Router,
    armed: shutdown::Armed,
) -> std::io::Result<shutdown::Stopped> {
    use axum::ServiceExt as _;
    use tower::Layer as _;
    let mut served: std::io::Result<()> = Ok(());
    if !armed.is_draining() {
        let AppListener {
            listener,
            admission,
            tag,
        } = app;
        let work = WorkLayer {
            count: armed.work_count(),
        };
        let svc = crate::inbound_authority::HostAdmissionLayer::new(admission, tag)
            .layer(work.layer(CanonicalUrl::new(router)));
        let mut stop = armed.drain();
        let serve = std::future::IntoFuture::into_future(
            axum::serve(
                listener,
                svc.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(async move { stop.wait().await }),
        );
        served = serve_until_drained(serve, &armed).await;
    }
    stop_after_serve(&armed, served).await
}

/// Run `serve` until it ends, or until the drain plus what is left of the
/// grace; the site counts as live throughout.
async fn serve_until_drained(
    serve: impl std::future::Future<Output = std::io::Result<()>> + Send,
    armed: &shutdown::Armed,
) -> std::io::Result<()> {
    // This site counts as live while it serves, so a sibling site sharing
    // the owner closes the shared pools only after this one has drained.
    let serving = armed.drain().hold();
    tokio::pin!(serve);
    let mut drain = armed.drain();
    let mut served = Ok(());
    tokio::select! {
        biased;
        ended = serve.as_mut() => served = ended,
        () = drain.wait() => {
            if let Ok(ended) = tokio::time::timeout(armed.remaining_grace(), serve.as_mut()).await {
                served = ended;
            }
        }
    }
    drop(serving);
    served
}

/// Tear the owner down after a stopping serve; hand back an unsignalled
/// serve's end untouched.
async fn stop_after_serve(
    armed: &shutdown::Armed,
    served: std::io::Result<()>,
) -> std::io::Result<shutdown::Stopped> {
    if !armed.signalled() && !armed.is_draining() {
        return served.and_then(|()| {
            Err(std::io::Error::other(
                "the serve loop ended before any shutdown signal",
            ))
        });
    }
    armed.settle_live().await;
    let settled = armed.cancel_work().await;
    #[cfg(all(feature = "web", feature = "http_client"))]
    crate::web::flush_exporters().await;
    let closed = shutdown::close_owned_pools(armed, settled).await;
    served.map(|()| shutdown::Stopped::after(closed))
}

/// Serve a test upstream `router` on `listener` with no Host admission.
///
/// The test modules' one serve site: exporter and proxy upstreams stand in for
/// a remote peer on `127.0.0.1:0`, never for an app listener.
#[cfg(all(test, feature = "web", feature = "http_client"))]
#[allow(clippy::disallowed_methods)] // test upstreams stand in for remote peers, never an app listener
pub(crate) async fn serve_fixture(
    listener: tokio::net::TcpListener,
    router: axum::Router,
) -> std::io::Result<()> {
    axum::serve(listener, router).await
}

/// One raw HTTP/1.1 exchange with the app listener on `127.0.0.1:port`: send
/// `request` verbatim and return the whole response text, or `None` when no
/// connection opens within five seconds or the response is not UTF-8.
///
/// Raw bytes, so a test can send the `Host` a rebinding browser sends.
#[cfg(test)]
pub(crate) async fn raw_exchange(port: u16, request: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut stream = None;
    for _ in 0..100 {
        if let Ok(s) = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mut stream = stream?;
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut out = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read_to_end(&mut out),
    )
    .await
    .ok()?
    .ok()?;
    String::from_utf8(out).ok()
}

/// The status code of a raw HTTP/1.1 `response`, `0` when it has none.
#[cfg(test)]
pub(crate) fn raw_status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// A free loopback port: bound once, then released for the listener under test.
#[cfg(test)]
pub(crate) fn free_loopback_port() -> Option<u16> {
    let held = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).ok()?;
    held.local_addr().ok().map(|a| a.port())
}

/// The startup lines an app listener bound on `addr` prints, in order: where
/// it listens, which hosts it admits, then, for an exposed host, the
/// [`exposure_warning`].
///
/// One list, so the warning cannot be dropped without the `listening on`
/// readiness line every launcher waits for.
fn startup_lines(
    addr: std::net::SocketAddr,
    host: crate::app_config::ListenHost,
    names: &crate::inbound_authority::DeclaredNames,
) -> Vec<String> {
    let mut lines = vec![format!("listening on http://{addr}"), admission_line(names)];
    lines.extend(exposure_warning(host).into_iter().flatten());
    lines
}

/// The startup line naming which hosts an app listener admits; it counts the
/// declared names and never echoes one, and with none names the variable that
/// declares them.
fn admission_line(names: &crate::inbound_authority::DeclaredNames) -> String {
    const ADMITTED: &str = "host admission: IP literals and localhost";
    if names.is_empty() {
        format!(
            "{ADMITTED}; set {}=<name> to serve a DNS name",
            crate::env_registry::listen::ALLOWED_HOSTS.name()
        )
    } else {
        format!("{ADMITTED}, and {} declared name(s)", names.len())
    }
}

/// The startup warning an exposed app listener prints, one message per line;
/// `None` for a loopback listener.
///
/// The address is the parsed `IpAddr`, never the raw `IPE_HTTP_BIND` text.
pub(crate) fn exposure_warning(host: crate::app_config::ListenHost) -> Option<[String; 2]> {
    use crate::app_config::{ExposedBy, ListenHost};
    let ListenHost::Exposed { ip, by } = host else {
        return None;
    };
    let reach = if ip.is_unspecified() {
        format!("every interface ({ip})")
    } else {
        ip.to_string()
    };
    let (cause, keep_local) = match by {
        ExposedBy::EnvVar => (
            format!("IPE_HTTP_BIND={ip}"),
            "unset IPE_HTTP_BIND (the default is 127.0.0.1)",
        ),
        ExposedBy::Setting => (
            "the app sets Host.bind Host.allInterfaces".to_owned(),
            "set Host.bind Host.loopback, or IPE_HTTP_BIND=127.0.0.1",
        ),
    };
    Some([
        format!(
            "warning: listening on {reach} because {cause}; other hosts on the network can reach this app"
        ),
        format!("  to keep it local, {keep_local}"),
    ])
}

pub fn server_listen<E: crate::FromIpeError + Send + 'static>(
    port: i64,
    routes: Vec<ServerRoute>,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        let refuse = |refusal: ServerStartRefusal| -> IpeResult<E, ()> {
            IpeResult::Err(E::from_ipe_error(refusal.into_ipe_error()))
        };
        // Every endpoint path is parsed once before any insert or bind: a
        // pattern the router could misread, or one no request could reach,
        // refuses the whole route set. The router sees only the rendered
        // spelling, never the author's text.
        let routes = match parse_routes(routes) {
            Ok(routes) => routes,
            Err(refusal) => return refuse(ServerStartRefusal::Route(refusal)),
        };
        // Fail-closed endpoint-conflict gate (see `endpoint_conflict`): refuse an
        // overlapping handler set with a typed error before any router insert,
        // so a router conflict can never panic the listener task.
        if let Some(refusal) = endpoint_conflict(&routes).or_else(|| mount_conflict(&routes)) {
            return refuse(refusal);
        }
        // Bind host obeys the one runtime-config precedence: `IPE_HTTP_BIND`
        // (env) > the app's `Host.bind` setting > `127.0.0.1`. A present
        // `IPE_HTTP_BIND` that is not an IP address refuses the listener.
        let host = match crate::app_config::resolve_host_bind() {
            Ok(host) => host,
            Err(refusal) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                    "Server.listen: {refusal}"
                ))));
            }
        };
        let ceilings = match listen_ceilings() {
            Ok(ceilings) => ceilings,
            Err(refusal) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                    "Server.listen: {refusal}"
                ))));
            }
        };
        // A revocation mode the env names but the runtime cannot parse refuses
        // the listener in every build, so an operator's typo is never accepted;
        // the authed routes already treat it as armed.
        if let Err(refusal) = crate::app_config::revocation_env() {
            return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                "Server.listen: {refusal}"
            ))));
        }
        // The framing policy every response carries is parsed before bind, so
        // a value with no header representation refuses the listener.
        if let Err(refusal) = crate::telemetry::frame_ancestors_config() {
            return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                "Server.listen: {refusal}"
            ))));
        }
        let mut app: axum::Router = axum::Router::new();
        let mut mounts = Vec::new();
        for r in routes {
            match r.target {
                ParsedTarget::Static(base, dir) => {
                    let files = axum::Router::new()
                        .fallback_service(strict_serve_dir(std::path::PathBuf::from(dir)));
                    mounts.push((base, files));
                }
                ParsedTarget::Handler(method, pattern, h) => {
                    let endpoint = quoted_endpoint(&r.method.to_uppercase(), &r.path);
                    let path = pattern.router_path().to_owned();
                    let mr = method_router(method, pattern, h);
                    app = match insert_endpoint(app, &path, mr, endpoint) {
                        Ok(next) => next,
                        Err(refusal) => return refuse(refusal),
                    };
                }
                // `Server.mountApp`: build the embedded web app's router for its
                // parsed base and serve it below that prefix on this same
                // listener (one port). Each app carries its own base in its
                // state, so any number of apps mount at distinct prefixes. The
                // builder is taken once; a duplicate (a cloned route) finds
                // `None` and is skipped — inert.
                #[cfg(feature = "web")]
                ParsedTarget::MountWeb(base, cell) => {
                    let builder = cell
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(build) = builder {
                        let sub = build(base.clone()).await;
                        mounts.push((base, sub));
                    }
                }
            }
        }
        let app = MountTable::new(mounts).below(app);
        // Ipê doctrine: a panicking handler returns 500, never crashes the
        // process. The custom
        // responder classifies + logs the panic SERVER-SIDE (errId) and returns a
        // 500 carrying ONLY the errId — never the panic message (no info leak).
        let app = app.layer(tower_http::catch_panic::CatchPanicLayer::custom(
            |err: Box<dyn std::any::Any + Send + 'static>| {
                use axum::response::IntoResponse;
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    crate::core::panic_500_body(&*err),
                )
                    .into_response()
            },
        ));
        // DoS ceilings (fail-closed, present by construction): the global
        // in-flight concurrency cap bounds fan-out; the per-request timeout
        // bounds how long any single connection can pin a worker (slowloris).
        // `.layer` wraps outer-last, so applying the timeout AFTER the
        // concurrency limit puts it OUTERMOST — a request that cannot acquire a
        // concurrency permit still resolves to a timeout rather than parking
        // forever behind the cap.
        let app = app
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(
                ceilings.max_inflight,
            ))
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(ceilings.request_timeout_secs),
            ));
        // Port precedence: the supervisor's relocation var (`ipe dev watch` placing
        // the app behind its proxy) > `IPE_SERVER_PORT` (operator) > the port the
        // program passed to `Server.listen`. A set env layer that is not a port
        // refuses the listen, naming its variable; no layer can yield `0`.
        let Some(source) = crate::system::SourcePort::parse(port) else {
            return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                "Server.listen: port {port} is not a TCP port in 1..=65535"
            ))));
        };
        let resolved = match crate::system::listen_port_from_env(
            crate::env_registry::listen::SERVER_PORT,
            source,
        ) {
            Ok(resolved) => resolved,
            Err(refusal) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                    "Server.listen: {refusal}"
                ))));
            }
        };
        let port = resolved.port.get();
        let grace = match shutdown::shutdown_grace() {
            Ok(grace) => grace,
            Err(refusal) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                    "Server.listen: {refusal}"
                ))));
            }
        };
        // Armed before the bind, so no accepted connection precedes the owner.
        let armed = match shutdown::arm(shutdown::ShutdownPlan::server(), grace) {
            Ok(armed) => armed,
            Err(e) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::io(format!(
                    "Server.listen: shutdown signals: {}",
                    crate::system::scrub_log_controls(&e.to_string())
                ))));
            }
        };
        // Recorded before the bind, so no dev surface outlives an exposed listener.
        let host = RecordedHost::record(host);
        let addr = host.addr(port);
        let listener = match bind_app_listener("http.server", host, port).await {
            Ok(l) => l,
            Err(AppBindError::Admission(refusal)) => {
                return IpeResult::Err(E::from_ipe_error(IpeError::invalid_input(format!(
                    "Server.listen: {refusal}"
                ))));
            }
            Err(AppBindError::Bind(e)) => {
                return IpeResult::Err(E::from_ipe_error(resolved.bind_refusal(
                    "Server.listen",
                    addr,
                    &e,
                )));
            }
        };
        // `serve_app` serves with connect-info, so each request carries the peer
        // `SocketAddr` (`ServerRequest.remoteAddr`, per-IP rate limiting).
        match serve_app(listener, app, armed).await {
            Ok(shutdown::Stopped { .. }) => ok_res(()),
            Err(e) => IpeResult::Err(E::from_ipe_error(IpeError::io(format!(
                "Server.listen: serve: {}",
                crate::system::scrub_log_controls(&e.to_string())
            )))),
        }
    })
}

// ─── Ipe.Http.Server.WebSocket ────────────────────────────────────────────
//
// Bridged types (runtimeOpaqueTypes): WebSocketServer -> WsHandle (the opaque
// per-peer handle the stdlib pattern-matches as `WebSocketServer raw`);
// WebSocketServerCfg -> WsServerCfg (fn-pointer callbacks so the stdlib's
// `defaultCfg |> withOnX` record updates compile — see the design doc on why
// non-capturing handlers are the first-cut limit).

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Ipe.Http.Server.WebSocket.WebSocketServer — opaque per-peer handle. The
/// variant name matches the Ipê constructor so `case sock of WebSocketServer
/// raw` lowers onto it.
#[derive(Clone, Copy, Debug)]
pub enum WsHandle {
    WebSocketServer(i64),
}

crate::stringify::show_row!("WebSocketServer", Internals, [] WsHandle, |_| "<Ipe.Http.Server.WebSocket>".to_owned());

/// Ipe.Http.Server.WebSocket.WebSocketServerCfg — fn-pointer callbacks (cannot
/// capture; capturing handlers need Arc<dyn Fn> erasure, a follow-up).
///
/// Generic over the error type E because the project's concrete error
/// (IpeCoreErrorError) is unnameable from the runtime crate. The Ipê-side
/// bridge pins `E = IpeError` (and drops the phantom `msg`) via a generic type
/// alias — see aliasToRustTypeDef. fn pointers don't store E, so WsServerCfg<E>
/// is Send/Copy-of-fields regardless of E.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct WsServerCfg<E> {
    // Stored effectful callbacks. These are `Arc<dyn Fn + Send + Sync>`, NOT
    // bare `fn` pointers: a real handler captures app state (the SSE-relay shape
    // proves capturing closures are first-class — see ex-32), and a captured
    // closure is not a `fn` pointer. The codegen renders function-typed record
    // fields as `Arc<dyn Fn(..) -> .. + Send + Sync>` and wraps the assigned
    // value in `Arc::new(..)` at every record literal / field-update site, so
    // the `withOnX` setters (param `impl Fn`) and `defaultCfg` (lambda literals)
    // both store cleanly. Arc is Clone, so the `#[derive(Clone)]` above holds.
    pub onConnect: Arc<dyn Fn(WsHandle) -> IpeTask<E, ()> + Send + Sync>,
    pub onMessage: Arc<dyn Fn(WsHandle, String) -> IpeTask<E, ()> + Send + Sync>,
    pub onClose: Arc<dyn Fn(WsHandle) -> IpeTask<E, ()> + Send + Sync>,
    pub onError: Arc<dyn Fn(WsHandle, E) -> IpeTask<E, ()> + Send + Sync>,
    pub maxMessageBytes: i64,
    pub originPatterns: Vec<String>,
}

crate::stringify::show_row!("WebSocketServerCfg", Internals, [E] WsServerCfg<E>, |_| "<Ipe.Http.Server.WebSocket.Config>".to_owned());

enum WsOut {
    Text(String),
    Binary(Vec<u8>),
    Close,
}

/// Per-peer outbound queue depth. A slow/idle WebSocket consumer must NOT let the
/// server buffer unboundedly (OOM) — the channel is bounded and a full queue drops
/// the message (the send kernel returns Err), giving real backpressure. Override
/// via `IPE_WS_SEND_BUFFER`; default 256 frames.
const WS_SEND_BUFFER_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WS_SEND_BUFFER",
    256,
    crate::system::ZeroCeiling::Refused,
    "decimal frame count",
)
.at_most(tokio::sync::Semaphore::MAX_PERMITS as u64);

/// Live-peer ceiling. Each accepted upgrade pins a registry slot, an mpsc
/// channel, and a heartbeat task; without a ceiling a peer can open connections
/// until FD/memory exhaustion. Override via `IPE_WS_MAX_CONNECTIONS`; default
/// 1024, mirroring `http_stream`'s `CLIENT_STREAMS_MAX`.
const WS_MAX_CONNECTIONS_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WS_MAX_CONNECTIONS",
    1024,
    crate::system::ZeroCeiling::Refused,
    "decimal connection count",
);

/// Heartbeat interval for WebSocket Ping frames: `IPE_WS_HEARTBEAT` seconds, default 30.
const WS_HEARTBEAT_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_WS_HEARTBEAT",
    30,
    crate::system::ZeroCeiling::Refused,
    "decimal second count",
);

/// The ceilings one WebSocket peer runs under, resolved at its upgrade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WsCeilings {
    /// The outbound queue depth, in frames.
    send_buffer: usize,
    /// The live-peer ceiling.
    max_connections: usize,
    /// The Ping interval, in seconds.
    heartbeat_secs: u64,
}

fn ws_ceilings() -> Result<WsCeilings, crate::system::EnvCeilingRefusal> {
    Ok(WsCeilings {
        send_buffer: WS_SEND_BUFFER_CEILING.read()?,
        max_connections: WS_MAX_CONNECTIONS_CEILING.read()?,
        heartbeat_secs: WS_HEARTBEAT_CEILING.read()?,
    })
}

fn ws_registry() -> &'static Mutex<HashMap<i64, tokio::sync::mpsc::Sender<WsOut>>> {
    static R: OnceLock<Mutex<HashMap<i64, tokio::sync::mpsc::Sender<WsOut>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

static WS_NEXT_ID: AtomicI64 = AtomicI64::new(1);

#[cfg(feature = "jwt")]
tokio::task_local! {
    // The credentials the in-flight request is bound to; fresh and empty per
    // dispatch.
    static SERVER_REQUEST: Arc<Mutex<crate::revocation::SessionBindings>>;
}

/// Run `request` as one `Server` dispatch, inside a fresh, empty binding set.
///
/// Only code that runs while `request` is polled is inside the scope: a
/// handler CALLED to build `request` ran before it, so a dispatch goes
/// through [`dispatch`], which calls the handler inside.
#[cfg(feature = "jwt")]
pub(crate) async fn in_request_scope<F: Future>(request: F) -> F::Output {
    SERVER_REQUEST.scope(Arc::default(), request).await
}

/// Run `request` as one `Server` dispatch; without `jwt` no credential exists
/// to bind.
#[cfg(not(feature = "jwt"))]
async fn in_request_scope<F: Future>(request: F) -> F::Output {
    request.await
}

/// Run `h` on `req` as one `Server` dispatch.
///
/// The handler is called inside the request scope, not only awaited there: an
/// emitted handler runs its pure code (an `Auth.verifyToken` match) when it is
/// called, and that code binds into the request's set. Returns the outcome
/// beside the request's stream table, which only its response may claim.
async fn dispatch(
    h: &ErasedHandler,
    req: ServerRequest,
) -> (Result<ServerResponse, String>, RequestStreams) {
    crate::server_stream::in_stream_scope(in_request_scope(async move { h(req).await })).await
}

/// The binding set of the `Server` request the current task handles, or
/// `None` outside any dispatch.
#[cfg(feature = "jwt")]
pub(crate) fn request_bindings() -> Option<Arc<Mutex<crate::revocation::SessionBindings>>> {
    SERVER_REQUEST.try_with(Arc::clone).ok()
}

/// `task`, run inside the binding set of the `Server` request the caller
/// handles, so work spawned on that request's behalf binds into it.
///
/// The set is read when this is called, on the caller's task.
#[cfg(feature = "jwt")]
pub(crate) fn inherit_request_scope<F: Future>(task: F) -> impl Future<Output = F::Output> {
    let bindings = request_bindings();
    async move {
        match bindings {
            Some(bindings) => SERVER_REQUEST.scope(bindings, task).await,
            None => task.await,
        }
    }
}

/// How long a gated channel waits after a revocation before it re-proves.
///
/// One recheck per interval answers any number of revocations, so a party
/// that can trigger revocations cannot amplify the recheck cost.
#[cfg(feature = "jwt")]
pub(crate) const RECHECK_COALESCE: std::time::Duration = std::time::Duration::from_secs(1);

/// The close reason a gated channel sends once its credentials no longer hold.
const CHANNEL_DENIED_REASON: &str = "credential revoked";

/// Why a gated channel ends, or never opens.
#[cfg(feature = "jwt")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChannelDenial {
    /// A credential the channel holds no longer passes the gate.
    Credential(crate::revocation::Denial),
    /// The armed process opened a channel outside any `Server` request: no
    /// binding set exists to re-prove.
    Unscoped,
}

#[cfg(feature = "jwt")]
impl From<crate::revocation::Denial> for ChannelDenial {
    fn from(denial: crate::revocation::Denial) -> Self {
        Self::Credential(denial)
    }
}

#[cfg(feature = "jwt")]
impl std::fmt::Display for ChannelDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Credential(denial) => denial.fmt(f),
            Self::Unscoped => f.write_str("channel opened outside any Server request"),
        }
    }
}

/// Why a gated channel ends; without `jwt` no channel is gated.
#[cfg(not(feature = "jwt"))]
pub(crate) enum ChannelDenial {}

/// The credentials a channel inherits from the code that opened it.
#[cfg(feature = "jwt")]
#[derive(Clone)]
pub(crate) enum ChannelCredentials {
    /// The binding set of the `Server` request that opened the channel.
    Request(Arc<Mutex<crate::revocation::SessionBindings>>),
    /// No `Server` request owns the code that opened the channel.
    Unscoped,
}

/// The credentials a channel inherits; without `jwt` there are none.
#[cfg(not(feature = "jwt"))]
#[derive(Clone)]
pub(crate) struct ChannelCredentials;

impl ChannelCredentials {
    /// The binding set of the `Server` request the current task handles.
    #[cfg(feature = "jwt")]
    pub(crate) fn of_request() -> Self {
        request_bindings().map_or(Self::Unscoped, Self::Request)
    }

    /// No binding set exists without `jwt`.
    #[cfg(not(feature = "jwt"))]
    pub(crate) const fn of_request() -> Self {
        Self
    }

    /// Call `callback` and run its task inside the channel's binding set, so
    /// a credential the channel's code verifies (in `onMessage`, in a stream
    /// handler) binds to the channel and is re-proved with it.
    #[cfg(feature = "jwt")]
    pub(crate) async fn scoped<F: Future>(&self, callback: impl FnOnce() -> F) -> F::Output {
        match self {
            Self::Request(bindings) => {
                SERVER_REQUEST
                    .scope(Arc::clone(bindings), async move { callback().await })
                    .await
            }
            Self::Unscoped => callback().await,
        }
    }

    /// Call `callback` and run its task; without `jwt` no binding set exists.
    #[cfg(not(feature = "jwt"))]
    #[allow(clippy::unused_self)] // the `jwt` build's signature, which reads the binding set
    pub(crate) async fn scoped<F: Future>(&self, callback: impl FnOnce() -> F) -> F::Output {
        callback().await
    }
}

/// The revocation gate of one long-lived channel (a WebSocket, a stream).
///
/// It holds the binding set of the request that opened the channel and
/// re-proves every bound credential on a revocation (coalesced over
/// [`RECHECK_COALESCE`]), at the earliest deadline, and whenever the channel
/// asks before it commits an action. The set is the channel's own: a
/// credential its code verifies later joins it.
#[cfg(feature = "jwt")]
pub(crate) struct ChannelGate {
    gate: crate::revocation::ArmedGate,
    bindings: Arc<Mutex<crate::revocation::SessionBindings>>,
    /// The size and earliest deadline of the set at the last recheck: a
    /// change means a credential joined since.
    proved: (usize, Option<crate::revocation::UnixSecs>),
    generation: tokio::sync::watch::Receiver<u64>,
    /// When the coalesced recheck a seen revocation owes is due.
    recheck_at: Option<tokio::time::Instant>,
    last_recheck: tokio::time::Instant,
    /// When the earliest bound credential reaches its deadline.
    deadline_at: Option<tokio::time::Instant>,
    opened_unix: i64,
    opened_at: tokio::time::Instant,
}

#[cfg(feature = "jwt")]
impl ChannelGate {
    /// The gate of a channel bound to `credentials`, re-proved once now.
    ///
    /// `None` when the process is unarmed. A request that bound nothing still
    /// gets a gate, since the channel's code may verify a credential later.
    ///
    /// # Errors
    ///
    /// The [`ChannelDenial`] of the opening recheck; a poisoned binding set is
    /// [`crate::revocation::Denial::StoreUnavailable`]; an armed process
    /// refuses a channel no `Server` request opened
    /// ([`ChannelDenial::Unscoped`]), since its credentials cannot be known.
    pub(crate) fn open(credentials: &ChannelCredentials) -> Result<Option<Self>, ChannelDenial> {
        use crate::revocation::{ArmedGate, process_mode, subscribe};
        // Subscribed before the opening recheck: a revocation that lands after
        // the recheck read the store is still seen as a generation change.
        let generation = subscribe();
        let Some(gate) = ArmedGate::resolve(process_mode()) else {
            return Ok(None);
        };
        let ChannelCredentials::Request(bindings) = credentials else {
            return Err(ChannelDenial::Unscoped);
        };
        let bindings = Arc::clone(bindings);
        let now = tokio::time::Instant::now();
        let mut channel = Self {
            gate,
            bindings,
            proved: (0, None),
            generation,
            recheck_at: None,
            last_recheck: now,
            deadline_at: None,
            opened_unix: crate::jwt::now_unix_seconds(),
            opened_at: now,
        };
        channel.recheck()?;
        Ok(Some(channel))
    }

    /// The current Unix second: the wall clock, never behind the monotonic
    /// time elapsed since the channel opened.
    fn now_unix(&self) -> i64 {
        let elapsed = i64::try_from(self.opened_at.elapsed().as_secs()).unwrap_or(i64::MAX);
        crate::jwt::now_unix_seconds().max(self.opened_unix.saturating_add(elapsed))
    }

    /// Re-prove every bound credential now, and re-arm the deadline.
    ///
    /// Every generation already observed is marked seen BEFORE the store is
    /// read, so a revocation that lands after the read is a later change.
    ///
    /// # Errors
    ///
    /// The first [`ChannelDenial`] of any bound credential; a poisoned binding
    /// set is [`crate::revocation::Denial::StoreUnavailable`].
    pub(crate) fn recheck(&mut self) -> Result<(), ChannelDenial> {
        self.generation.mark_unchanged();
        self.recheck_at = None;
        let now = tokio::time::Instant::now();
        self.last_recheck = now;
        let now_unix = self.now_unix();
        let held = self
            .bindings
            .lock()
            .map_err(|_| crate::revocation::Denial::StoreUnavailable)?;
        held.recheck_all(self.gate, now_unix)?;
        let earliest = held.earliest_deadline();
        self.proved = (held.len(), earliest);
        self.deadline_at = earliest.and_then(|deadline| {
            let left = u64::try_from(deadline.get().saturating_sub(now_unix)).unwrap_or(0);
            now.checked_add(std::time::Duration::from_secs(left))
        });
        Ok(())
    }

    /// Re-prove now when a credential joined the set since the last recheck,
    /// or when a seen revocation's coalesced recheck is due.
    ///
    /// Called between the channel's actions, so an owed denial ends the
    /// channel before its next action, whatever order its waits resolve in.
    ///
    /// # Errors
    ///
    /// As [`Self::recheck`].
    pub(crate) fn settle(&mut self) -> Result<(), ChannelDenial> {
        let now = tokio::time::Instant::now();
        let coalesced = self
            .last_recheck
            .checked_add(RECHECK_COALESCE)
            .is_none_or(|at| at <= now);
        let revoked = self.recheck_at.is_some_and(|at| at <= now)
            || (coalesced && self.generation.has_changed().unwrap_or(true));
        let joined = {
            let held = self
                .bindings
                .lock()
                .map_err(|_| crate::revocation::Denial::StoreUnavailable)?;
            (held.len(), held.earliest_deadline()) != self.proved
        };
        if revoked || joined {
            self.recheck()
        } else {
            Ok(())
        }
    }

    /// Wait until the channel owes a recheck: `Ok` once a coalesced revocation
    /// recheck is due, a denial once the earliest deadline is reached.
    ///
    /// Cancel-safe: the owed recheck is kept in the gate, never in the future.
    ///
    /// # Errors
    ///
    /// [`crate::revocation::Denial::PastDeadline`] at the deadline;
    /// [`crate::revocation::Denial::StoreUnavailable`] when the generation can
    /// no longer be observed.
    pub(crate) async fn due(&mut self) -> Result<(), ChannelDenial> {
        use crate::revocation::Denial;
        loop {
            if let Some(at) = self.recheck_at {
                tokio::select! {
                    () = tokio::time::sleep_until(at) => return Ok(()),
                    () = deadline_sleep(self.deadline_at) => return Err(Denial::PastDeadline.into()),
                }
            }
            tokio::select! {
                changed = self.generation.changed() => {
                    changed.map_err(|_| Denial::StoreUnavailable)?;
                    let now = tokio::time::Instant::now();
                    self.recheck_at = Some(
                        self.last_recheck
                            .checked_add(RECHECK_COALESCE)
                            .map_or(now, |at| at.max(now)),
                    );
                }
                () = deadline_sleep(self.deadline_at) => return Err(Denial::PastDeadline.into()),
            }
        }
    }
}

/// Sleep until `at`; forever when there is no deadline.
#[cfg(feature = "jwt")]
async fn deadline_sleep(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The revocation gate of a long-lived channel; without `jwt` no channel is
/// gated, so no gate exists.
#[cfg(not(feature = "jwt"))]
pub(crate) enum ChannelGate {}

#[cfg(not(feature = "jwt"))]
impl ChannelGate {
    /// No channel is gated without `jwt`.
    #[allow(clippy::unnecessary_wraps)] // the `jwt` build's signature, which can refuse
    pub(crate) const fn open(
        _credentials: &ChannelCredentials,
    ) -> Result<Option<Self>, ChannelDenial> {
        Ok(None)
    }

    /// Uninhabited: no gate exists to recheck.
    pub(crate) fn recheck(&mut self) -> Result<(), ChannelDenial> {
        match *self {}
    }

    /// Uninhabited: no gate exists to settle.
    pub(crate) fn settle(&mut self) -> Result<(), ChannelDenial> {
        match *self {}
    }

    /// Uninhabited: no gate exists to wait on.
    pub(crate) fn due(&mut self) -> std::future::Ready<Result<(), ChannelDenial>> {
        match *self {}
    }
}

/// Wait until `gate` denies: each owed recheck that passes keeps waiting, and
/// an ungated channel waits forever.
///
/// Cancel-safe, as [`ChannelGate::due`] is.
pub(crate) async fn channel_denial(gate: &mut Option<ChannelGate>) {
    let Some(gate) = gate.as_mut() else {
        return std::future::pending().await;
    };
    loop {
        if gate.due().await.and_then(|()| gate.recheck()).is_err() {
            return;
        }
    }
}

/// Whether `gate` refuses the action the channel is about to commit.
fn channel_refuses(gate: &mut Option<ChannelGate>) -> bool {
    gate.as_mut().is_some_and(|gate| gate.recheck().is_err())
}

/// Whether `gate`, settled between two actions, refuses the next one.
pub(crate) fn channel_unsettled(gate: &mut Option<ChannelGate>) -> bool {
    gate.as_mut().is_some_and(|gate| gate.settle().is_err())
}

/// The close frame a WebSocket sends when the server stops serving it.
fn ws_away_close() -> axum::extract::ws::Message {
    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
        code: axum::extract::ws::close_code::AWAY,
        reason: "server shutting down".into(),
    }))
}

/// The close frame a gated WebSocket sends once its credentials no longer hold.
fn ws_denied_close() -> axum::extract::ws::Message {
    axum::extract::ws::Message::Close(Some(axum::extract::ws::CloseFrame {
        code: axum::extract::ws::close_code::POLICY,
        reason: CHANNEL_DENIED_REASON.into(),
    }))
}

/// Send the close `frame`, waiting at most [`shutdown::WS_CLOSE_DEADLINE`]: a
/// peer that stops reading never holds the socket's loop, its `onClose` or its
/// registry slot past the deadline.
async fn ws_send_close<S>(socket: &mut S, frame: axum::extract::ws::Message)
where
    S: futures_util::Sink<axum::extract::ws::Message> + Unpin,
{
    use futures_util::SinkExt;
    let _ = tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE, socket.send(frame)).await;
}

tokio::task_local! {
    // The axum upgrader for the in-flight request (Some only on a WS upgrade).
    static WS_UPGRADER: std::cell::Cell<Option<axum::extract::ws::WebSocketUpgrade>>;
    // The 101 response server_web_socket_upgrade produced (preferred by method_router).
    static WS_RESPONSE: std::cell::Cell<Option<axum::response::Response>>;
}

/// Resolve the configured per-message byte cap, mirroring  `SetReadLimit`:
/// treat 0/negative as "unset" and apply the 1 MiB default
/// (`wsDefaultMaxMessageBytes = 1 << 20` in ``).
/// `try_from` avoids a wrapping/truncating cast on a caller-controlled `i64`.
/// Shared by `server_web_socket_upgrade` (framing-layer enforcement, applied
/// to the `WebSocketUpgrade` builder before the frame is even buffered) and
/// `ws_loop` (application-layer defense in depth on the already-decoded
/// message).
fn ws_max_message_bytes(max_message_bytes: i64) -> usize {
    if max_message_bytes > 0 {
        usize::try_from(max_message_bytes).unwrap_or(1 << 20)
    } else {
        1 << 20 // 1 MiB
    }
}

/// Serve one upgraded WebSocket until either side closes it.
///
/// Every callback runs inside `credentials`, so a token it verifies binds to
/// the socket. A gated socket (`gate` is `Some`) re-proves its credentials
/// before `onConnect`, before each inbound frame reaches `onMessage`, and on
/// every heartbeat; between any two actions it re-proves a credential that
/// joined and a revocation whose coalesced recheck is due; it also ends on a
/// coalesced revocation and at the earliest deadline. A denial sends close
/// code 1008 and ends the loop.
///
/// The drain counts the socket until `onClose` returns. Once it drains, the
/// socket sends close code 1001 and ends the loop. Every close frame goes
/// through [`ws_send_close`], under [`shutdown::WS_CLOSE_DEADLINE`].
///
/// The socket is one unit of shutdown work too: a callback still running when
/// the shutdown closes is cancelled, and no callback starts after it, so no
/// user code on the socket outlives the pools it may use.
async fn ws_loop<E, S>(
    mut socket: S,
    cfg: WsServerCfg<E>,
    id: i64,
    ceilings: WsCeilings,
    credentials: ChannelCredentials,
    mut gate: Option<ChannelGate>,
    mut drain: shutdown::Drain,
) where
    E: From<String> + Send + 'static,
    S: futures_util::Stream<Item = Result<axum::extract::ws::Message, axum::Error>>
        + futures_util::Sink<axum::extract::ws::Message>
        + Unpin,
{
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    let max_bytes: usize = ws_max_message_bytes(cfg.maxMessageBytes);
    // Framing-layer enforcement lives on the `WebSocketUpgrade` builder, applied
    // at upgrade time in `server_web_socket_upgrade` (`.max_message_size()` /
    // `.max_frame_size()` — axum 0.7.9 exposes both). A frame over the cap is
    // rejected by tokio-tungstenite before it reaches this loop. The Text/Binary
    // size checks below are application-layer defense in depth (belt-and-braces
    // against a future axum/tungstenite version silently dropping the cap).
    // A credential revoked between the upgrade and now opens nothing: no
    // registration, no `onConnect`.
    if channel_refuses(&mut gate) {
        ws_send_close(&mut socket, ws_denied_close()).await;
        return;
    }
    let Some(_live) = drain.hold() else {
        ws_send_close(&mut socket, ws_away_close()).await;
        return;
    };
    let Ok(mut work) = drain.work() else {
        ws_send_close(&mut socket, ws_away_close()).await;
        return;
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<WsOut>(ceilings.send_buffer);
    // Live-peer ceiling, application-layer defense in depth: the upgrade gate in
    // `server_web_socket_upgrade` is the primary check, but under high
    // concurrency the check-then-insert is a TOCTOU window. Re-check under the
    // same lock that inserts, so the count that admits the peer is the count that
    // grows — never insert past the ceiling. On overflow drop the socket with a
    // Close frame instead of registering it (no `onConnect`, no slot held).
    let admitted = {
        let mut reg = ws_registry().lock().unwrap_or_else(|e| e.into_inner());
        if reg.len() >= ceilings.max_connections {
            false
        } else {
            reg.insert(id, tx);
            true
        }
        // guard dropped here — never held across the awaits below.
    };
    if !admitted {
        ws_send_close(&mut socket, Message::Close(None)).await;
        return;
    }
    let connected = work
        .unless_cancelled(credentials.scoped(|| (cfg.onConnect)(WsHandle::WebSocketServer(id))))
        .await;
    if connected.is_none() {
        ws_close_cancelled(socket, id, work).await;
        return;
    }
    // Heartbeat: send a Ping every `ceilings.heartbeat_secs` seconds to keep the
    // connection alive through proxies and detect silent drops.  Mirrors
    // `wsDefaultPingInterval = 30s` + `wsPingTimeout = 10s` pattern in
    // ``.  axum auto-replies to incoming Pong
    // frames on our behalf, so we only need to send the Ping here.
    let mut heartbeat = tokio::time::interval(Duration::from_secs(ceilings.heartbeat_secs));
    heartbeat.tick().await; // consume the immediate first tick
    loop {
        if channel_unsettled(&mut gate) {
            ws_send_close(&mut socket, ws_denied_close()).await;
            break;
        }
        tokio::select! {
            biased;
            () = channel_denial(&mut gate) => {
                ws_send_close(&mut socket, ws_denied_close()).await;
                break;
            },
            () = drain.wait() => {
                ws_send_close(&mut socket, ws_away_close()).await;
                break;
            },
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    if t.len() > max_bytes {
                        ws_send_close(&mut socket, Message::Close(None)).await;
                        break;
                    }
                    if channel_refuses(&mut gate) {
                        ws_send_close(&mut socket, ws_denied_close()).await;
                        break;
                    }
                    let handled = work
                        .unless_cancelled(
                            credentials.scoped(|| (cfg.onMessage)(WsHandle::WebSocketServer(id), t.as_str().to_owned())),
                        )
                        .await;
                    if handled.is_none() {
                        break;
                    }
                }
                Some(Ok(Message::Binary(b))) => {
                    if b.len() > max_bytes {
                        ws_send_close(&mut socket, Message::Close(None)).await;
                        break;
                    }
                    if channel_refuses(&mut gate) {
                        ws_send_close(&mut socket, ws_denied_close()).await;
                        break;
                    }
                    // Convert binary frame bytes to String via UTF-8 (lossy): Ipê's
                    // String invariant is valid UTF-8; non-UTF-8 binary replaces
                    // malformed sequences with U+FFFD rather than producing an
                    // ill-formed String. The server `onMessage` callback receives a
                    // uniform `String` for both text and binary frames; applications
                    // that need lossless binary round-trips should use a text+base64
                    // encoding at the Ipê level.
                    #[allow(clippy::disallowed_methods)] // a binary frame reaches `onMessage` as `String` text
                    let s = String::from_utf8_lossy(&b).into_owned();
                    let handled = work
                        .unless_cancelled(
                            credentials.scoped(|| (cfg.onMessage)(WsHandle::WebSocketServer(id), s)),
                        )
                        .await;
                    if handled.is_none() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => break,
                // Incoming Ping/Pong frames are auto-handled by axum; no user
                // callback needed.
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    let error = format!("ws read error: {}", e).into();
                    let _ = work
                        .unless_cancelled(
                            credentials.scoped(|| (cfg.onError)(WsHandle::WebSocketServer(id), error)),
                        )
                        .await;
                    break;
                }
            },
            outgoing = rx.recv() => match outgoing {
                Some(WsOut::Text(s)) => { if socket.send(Message::Text(s.into())).await.is_err() { break; } }
                Some(WsOut::Binary(b)) => { if socket.send(Message::Binary(b.into())).await.is_err() { break; } }
                Some(WsOut::Close) => { ws_send_close(&mut socket, Message::Close(None)).await; break; }
                None => break,
            },
            _ = heartbeat.tick() => {
                if channel_refuses(&mut gate) {
                    ws_send_close(&mut socket, ws_denied_close()).await;
                    break;
                }
                // Send a Ping frame; if the peer has gone away the send will
                // fail and we break, triggering onClose cleanup.
                if socket.send(Message::Ping(axum::body::Bytes::new())).await.is_err() {
                    break;
                }
            },
        }
    }
    let _ = work
        .unless_cancelled(credentials.scoped(|| (cfg.onClose)(WsHandle::WebSocketServer(id))))
        .await;
    ws_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
}

/// End a socket the shutdown cancelled before its loop began: unregister it,
/// release its work unit, then send the going-away close under its deadline.
async fn ws_close_cancelled<S>(mut socket: S, id: i64, work: shutdown::WorkGuard)
where
    S: futures_util::Sink<axum::extract::ws::Message> + Unpin,
{
    ws_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    drop(work);
    ws_send_close(&mut socket, ws_away_close()).await;
}

fn ws_resp(status: i64, body: &str) -> ServerResponse {
    ServerResponse {
        status,
        body: body.to_string(),
        headers: HashMap::new(),
        contentType: "text/plain".to_string(),
        cookies: Vec::new(),
    }
}

/// Glob match with `*` wildcards (e.g. "https://*.example.com"). `*` matches any
/// run of characters; all other chars are literal. Used for WS origin allowlists.
///
/// Security (CSWSH glob bypass): when a `*` is followed by a non-empty literal
/// anchor (a middle segment, or the trailing domain suffix), the region the `*`
/// covers MUST be a syntactic host fragment — `[A-Za-z0-9.:-]` only. Without this
/// a pattern like `https://*.example.com` would wrongly accept a forged origin
/// such as `https://evil.com/.example.com` or `https://evil.com@x.example.com`,
/// where the trusted suffix sits behind a path / userinfo delimiter. The explicit
/// allow-all pattern `*` (and any pattern ending in `*`) keeps matching anything —
/// that region has no literal anchor after it, so the user has opted into it.
fn ws_origin_matches(pattern: &str, origin: &str) -> bool {
    // A `*`-covered span that precedes a literal anchor may only contain host
    // characters — never a `/`, `@`, `?`, `#`, whitespace, or control byte that
    // could push the trusted literal behind a URL delimiter.
    fn host_safe(span: &str) -> bool {
        span.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == origin; // no wildcard → exact
    }
    let mut rest = origin;
    // First segment must be a prefix (unless pattern starts with '*').
    if let Some(first) = parts.first() {
        if !rest.starts_with(first) {
            return false;
        }
        rest = rest.get(first.len()..).unwrap_or("");
    }
    // Middle segments must appear in order. (parts.len() >= 2 here — the
    // len == 1 case returned early — so the slice is total.)
    for seg in parts.get(1..parts.len() - 1).unwrap_or(&[]) {
        if seg.is_empty() {
            continue;
        }
        match rest.find(seg) {
            Some(i) => {
                // `rest[..i]` was covered by the preceding `*`, and `seg` is a
                // literal anchor after it → enforce host-only.
                if !host_safe(rest.get(..i).unwrap_or("")) {
                    return false;
                }
                rest = rest.get(i + seg.len()..).unwrap_or("");
            }
            None => return false,
        }
    }
    // Last segment must be a suffix (unless pattern ends with '*').
    let last = parts.last().copied().unwrap_or("");
    if last.is_empty() {
        // Pattern ends with `*` → trailing region unrestricted (explicit allow-all).
        return true;
    }
    if !rest.ends_with(last) {
        return false;
    }
    // The span the trailing `*` covered (before the literal suffix) must be a host.
    host_safe(rest.get(..rest.len() - last.len()).unwrap_or(""))
}

/// True when `Origin` is present and does not match `Host` (cross-origin).
/// Absent `Origin` (same-origin browsers on older UA quirks, non-browser WS
/// clients, and legitimate same-origin pages under some proxy setups that
/// strip it) is NOT flagged — matches the equivalent CSRF/ingest same-origin
/// helpers elsewhere in this runtime (`csrf.rs::origin_mismatch`,
/// `console.rs::is_cross_origin_ingest`), via the shared `origin_host_mismatch`
/// helper in `http_header` (normalizes away each side's scheme-implied
/// default port so the three never drift to different behavior).
/// `http_header` is gated on `feature = "server"` only (not `live`), so this
/// reuse still builds standalone under `--features server` without `live`.
fn ws_cross_origin(req: &ServerRequest) -> bool {
    let origin = match header_ci(&req.headers, "origin") {
        Some(o) if !o.is_empty() => o,
        _ => return false,
    };
    let host = header_ci(&req.headers, "host").unwrap_or("");
    crate::http_header::origin_host_mismatch(origin, host)
}

/// The refusal for a WebSocket upgrade with no origin allowlist, if any.
///
/// Waived only under a [`DevSurface`](crate::telemetry::DevSurface): a dev
/// build whose every listener is loopback falls back to the same-origin check.
const fn ws_origin_decision(
    patterns_empty: bool,
    dev: Option<&crate::telemetry::DevSurface>,
) -> Option<(i64, &'static str)> {
    if patterns_empty && dev.is_none() {
        Some((403, "websocket: origin allowlist required in production"))
    } else {
        None
    }
}

/// ServerWebSocket_upgrade : Request -> WebSocketServerCfg -> Task Error Response
pub fn server_web_socket_upgrade<E: From<String> + Send + 'static>(
    req: ServerRequest,
    cfg: WsServerCfg<E>,
) -> IpeTask<E, ServerResponse> {
    Box::pin(async move {
        // Origin allowlist. No patterns and no dev surface → reject. With
        // patterns set (any mode), the request's Origin must match one of them.
        if let Some((status, body)) = ws_origin_decision(
            cfg.originPatterns.is_empty(),
            crate::telemetry::dev_surface_from_env().as_ref(),
        ) {
            return ok_res(ws_resp(status, body));
        }
        if !cfg.originPatterns.is_empty() {
            let origin = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
                .map(|(_, v)| v.as_str())
                .unwrap_or("");
            if !cfg
                .originPatterns
                .iter()
                .any(|p| ws_origin_matches(p, origin))
            {
                return ok_res(ws_resp(403, "websocket: origin not allowed"));
            }
        } else if ws_cross_origin(&req) {
            // Dev mode, no explicit allowlist: default to same-origin rather
            // than allow-all (closes CSWSH — Cross-Site WebSocket Hijacking. A
            // WS handshake can't carry a custom header, so unlike a
            // CSRF-protected form POST, Origin validation is the ONLY defense
            // available). Configure `Ws.withOriginPatterns` explicitly to
            // allow legitimate cross-origin clients.
            return ok_res(ws_resp(
                403,
                "websocket: cross-origin request rejected (set Ws.withOriginPatterns to allow)",
            ));
        }
        // Live-peer ceiling (fail-closed). Checked after the origin checks and
        // before the upgrader is taken, so it runs on EVERY path and before any
        // id/channel/task is minted — "allocated slot without a capacity check"
        // is unrepresentable. A race between this check and the registry insert
        // is closed by a re-check at the insert site in `ws_loop`.
        // A malformed ceiling refuses the upgrade rather than widening it.
        let Ok(ceilings) = ws_ceilings() else {
            return ok_res(ws_resp(503, "websocket: server ceiling misconfigured"));
        };
        // The socket inherits every credential this request bound; a gate
        // that cannot prove them now refuses the upgrade (fail closed).
        let credentials = ChannelCredentials::of_request();
        let Some(gate) = ChannelGate::open(&credentials).ok() else {
            return ok_res(ws_resp(401, "unauthorized"));
        };
        {
            let live = ws_registry()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len();
            if live >= ceilings.max_connections {
                return ok_res(ws_resp(503, "websocket: server at connection capacity"));
            }
        }
        let upgrader = WS_UPGRADER.try_with(|c| c.take()).ok().flatten();
        match upgrader {
            Some(up) => {
                let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
                // Enforce the cap at the framing layer: tokio-tungstenite rejects
                // an over-cap frame/message before it is ever fully buffered, so
                // the limit holds even before `ws_loop`'s in-loop check runs.
                let max_bytes = ws_max_message_bytes(cfg.maxMessageBytes);
                let up = up.max_message_size(max_bytes).max_frame_size(max_bytes);
                let drain = shutdown::drain();
                let resp = up.on_upgrade(move |socket| {
                    ws_loop(socket, cfg, id, ceilings, credentials, gate, drain)
                });
                let _ = WS_RESPONSE.try_with(|c| c.set(Some(resp)));
                // Sentinel — method_router returns WS_RESPONSE instead of this.
                ok_res(ServerResponse {
                    status: 101,
                    body: String::new(),
                    headers: HashMap::new(),
                    contentType: String::new(),
                    cookies: Vec::new(),
                })
            }
            None => ok_res(ws_resp(400, "websocket: expected an Upgrade request")),
        }
    })
}

fn ws_send_raw(id: i64, out: WsOut) -> bool {
    // try_send (non-blocking): a full per-peer queue (slow consumer) drops the
    // frame and returns false rather than buffering unboundedly — bounded memory.
    match ws_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
    {
        Some(tx) => tx.try_send(out).is_ok(),
        None => false,
    }
}

/// ServerWebSocket_sendToClient : Int -> String -> Task Error ()
pub fn server_web_socket_send_to_client<E: From<String> + Send + 'static>(
    id: i64,
    msg: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        if ws_send_raw(id, WsOut::Text(msg)) {
            ok_res(())
        } else {
            IpeResult::Err(format!("ws: no client {}", id).into())
        }
    })
}

/// ServerWebSocket_sendBinaryToClient : Int -> Bytes -> Task Error ()
pub fn server_web_socket_send_binary_to_client<E: From<String> + Send + 'static>(
    id: i64,
    msg: Vec<u8>,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        if ws_send_raw(id, WsOut::Binary(msg)) {
            ok_res(())
        } else {
            IpeResult::Err(format!("ws: no client {}", id).into())
        }
    })
}

/// ServerWebSocket_broadcast : List Int -> String -> Task Error ()
pub fn server_web_socket_broadcast<E: From<String> + Send + 'static>(
    ids: Vec<i64>,
    msg: String,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        let mut any_ok = false;
        {
            let reg = ws_registry().lock().unwrap_or_else(|e| e.into_inner());
            for id in &ids {
                if let Some(tx) = reg.get(id)
                    && tx.try_send(WsOut::Text(msg.clone())).is_ok()
                {
                    any_ok = true;
                }
            }
        }
        if ids.is_empty() || any_ok {
            ok_res(())
        } else {
            IpeResult::Err("ws broadcast: every send failed".to_string().into())
        }
    })
}

/// ServerWebSocket_closeClient : Int -> Task Error () (idempotent)
pub fn server_web_socket_close_client<E: From<String> + Send + 'static>(id: i64) -> IpeTask<E, ()> {
    Box::pin(async move {
        let _ = ws_send_raw(id, WsOut::Close);
        ok_res(())
    })
}

// ─── Ipe.Http.Server.WebSocket adapters ────────────────────────────
//
// Kernel-callable entry points (D3: handle-taking wrappers + cfg builders).
// The i64 family above is the registry API kept for upstream-sync; these
// adapters sit in front of it.
//
// Design decisions (docs/adr/0003-security-render-and-data-access-invariants.md):
//   D2 — WsServerCfg is monomorphic (pins E = IpeError, drops phantom msg).
//   D3 — kernels take WsHandle, not i64; adapters unwrap.
//   D4 — bounded fail-fast `try_send` (IPE_WS_SEND_BUFFER=256 default).

/// `Ws.defaultCfg` — no-op callbacks, `maxMessageBytes = 0` (→ 1 MiB in
/// `ws_loop`), empty `originPatterns` (dev: same-origin only — `Origin` must
/// match `Host` when `Origin` is present, `ws_cross_origin`; production: 403
/// on `upgrade`).
pub fn ws_server_default_cfg<E: From<String> + Send + 'static>() -> WsServerCfg<E> {
    WsServerCfg {
        onConnect: Arc::new(|_| Box::pin(async { ok_res(()) })),
        onMessage: Arc::new(|_, _| Box::pin(async { ok_res(()) })),
        onClose: Arc::new(|_| Box::pin(async { ok_res(()) })),
        onError: Arc::new(|_, _| Box::pin(async { ok_res(()) })),
        maxMessageBytes: 0,
        originPatterns: Vec::new(),
    }
}

/// `Ws.withOnConnect` — replace the `onConnect` callback.
///
/// Accepts `Arc<dyn Fn(WsHandle) -> IpeTask<E, ()> + Send + Sync + 'static>` directly
/// because stable Rust does not implement `Fn<Args>` for `Arc<dyn Fn<Args>>` — the
/// emitter always pre-wraps the function in `Arc::new`, so the adapter stores it as-is.
pub fn ws_server_with_on_connect<E>(
    cb: Arc<dyn Fn(WsHandle) -> IpeTask<E, ()> + Send + Sync + 'static>,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E>
where
    E: From<String> + Send + 'static,
{
    WsServerCfg {
        onConnect: cb,
        ..cfg
    }
}

/// `Ws.withOnMessage` — replace the `onMessage` callback.
///
/// The callback is uncurried (two args: `WsHandle` and `String`) to match
/// the `dict_foldl` uncurried precedent (see design doc §3).
///
/// Accepts `Arc<dyn Fn(...)>` directly — see `ws_server_with_on_connect` for rationale.
pub fn ws_server_with_on_message<E>(
    cb: Arc<dyn Fn(WsHandle, String) -> IpeTask<E, ()> + Send + Sync + 'static>,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E>
where
    E: From<String> + Send + 'static,
{
    WsServerCfg {
        onMessage: cb,
        ..cfg
    }
}

/// `Ws.withOnClose` — replace the `onClose` callback.
///
/// Accepts `Arc<dyn Fn(...)>` directly — see `ws_server_with_on_connect` for rationale.
pub fn ws_server_with_on_close<E>(
    cb: Arc<dyn Fn(WsHandle) -> IpeTask<E, ()> + Send + Sync + 'static>,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E>
where
    E: From<String> + Send + 'static,
{
    WsServerCfg { onClose: cb, ..cfg }
}

/// `Ws.withOnError` — replace the `onError` callback.
///
/// Accepts `Arc<dyn Fn(...)>` directly — see `ws_server_with_on_connect` for rationale.
pub fn ws_server_with_on_error<E>(
    cb: Arc<dyn Fn(WsHandle, E) -> IpeTask<E, ()> + Send + Sync + 'static>,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E>
where
    E: From<String> + Send + 'static,
{
    WsServerCfg { onError: cb, ..cfg }
}

/// `Ws.withMaxMessageBytes` — set per-message size cap (0 → 1 MiB default
/// in `ws_loop`).
pub fn ws_server_with_max_message_bytes<E: From<String> + Send + 'static>(
    n: i64,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E> {
    WsServerCfg {
        maxMessageBytes: n,
        ..cfg
    }
}

/// `Ws.withOriginPatterns` — set the origin allowlist.  Empty list = dev
/// allow-all; production mode with an empty list causes `upgrade` to return
/// 403 (see `server_web_socket_upgrade`).
pub fn ws_server_with_origin_patterns<E: From<String> + Send + 'static>(
    ps: Vec<String>,
    cfg: WsServerCfg<E>,
) -> WsServerCfg<E> {
    WsServerCfg {
        originPatterns: ps,
        ..cfg
    }
}

/// `Ws.sendToClient` — send a text frame.  D3: unwraps `WsHandle` before
/// delegating to the i64 registry family.
pub fn ws_server_send_to_client<E: From<String> + Send + 'static>(
    h: WsHandle,
    msg: String,
) -> IpeTask<E, ()> {
    let WsHandle::WebSocketServer(id) = h;
    server_web_socket_send_to_client(id, msg)
}

/// `Ws.sendBinaryToClient` — send a binary frame.  `Bytes = Vec<u8>` (ipe
/// divergence: upstream Ipe uses `Bytes = String`; see divergences doc §D2).
pub fn ws_server_send_binary_to_client<E: From<String> + Send + 'static>(
    h: WsHandle,
    data: Vec<u8>,
) -> IpeTask<E, ()> {
    let WsHandle::WebSocketServer(id) = h;
    server_web_socket_send_binary_to_client(id, data)
}

/// `Ws.broadcast` — best-effort text broadcast.  D3: unwraps each handle.
pub fn ws_server_broadcast<E: From<String> + Send + 'static>(
    hs: Vec<WsHandle>,
    msg: String,
) -> IpeTask<E, ()> {
    let ids: Vec<i64> = hs
        .into_iter()
        .map(|WsHandle::WebSocketServer(id)| id)
        .collect();
    server_web_socket_broadcast(ids, msg)
}

/// `Ws.closeClient` — close a peer connection.  D3; idempotent.
pub fn ws_server_close_client<E: From<String> + Send + 'static>(h: WsHandle) -> IpeTask<E, ()> {
    let WsHandle::WebSocketServer(id) = h;
    server_web_socket_close_client(id)
}

#[cfg(test)]
mod ws_adapter_tests {
    use super::*;

    #[test]
    fn default_cfg_max_message_bytes_is_zero() {
        // 0 → ws_loop applies the 1 MiB default; NOT a hard limit of 0.
        let cfg = ws_server_default_cfg::<String>();
        assert_eq!(cfg.maxMessageBytes, 0);
    }

    #[test]
    fn ws_max_message_bytes_zero_or_negative_is_1mib_default() {
        assert_eq!(ws_max_message_bytes(0), 1 << 20);
        assert_eq!(ws_max_message_bytes(-1), 1 << 20);
    }

    #[test]
    fn ws_max_message_bytes_positive_passes_through() {
        assert_eq!(ws_max_message_bytes(4096), 4096);
    }

    #[test]
    fn default_cfg_origin_patterns_empty() {
        let cfg = ws_server_default_cfg::<String>();
        assert!(cfg.originPatterns.is_empty());
    }

    #[test]
    fn with_max_message_bytes_sets_field() {
        let cfg = ws_server_default_cfg::<String>();
        let cfg2 = ws_server_with_max_message_bytes(4096, cfg);
        assert_eq!(cfg2.maxMessageBytes, 4096);
    }

    #[test]
    fn with_origin_patterns_sets_field() {
        let cfg = ws_server_default_cfg::<String>();
        let cfg2 = ws_server_with_origin_patterns(vec!["https://example.com".into()], cfg);
        assert_eq!(cfg2.originPatterns, vec!["https://example.com"]);
    }

    #[test]
    fn broadcast_empty_list_produces_empty_ids() {
        // The empty-list fast-path in server_web_socket_broadcast returns Ok(()).
        let hs: Vec<WsHandle> = Vec::new();
        let ids: Vec<i64> = hs
            .into_iter()
            .map(|WsHandle::WebSocketServer(id)| id)
            .collect();
        assert!(ids.is_empty());
    }

    #[test]
    fn handle_unwrap_roundtrip() {
        let h = WsHandle::WebSocketServer(99);
        let WsHandle::WebSocketServer(id) = h;
        assert_eq!(id, 99);
    }

    // ── server environment ceilings ───────────────────────────────────────────

    #[test]
    fn server_ceilings_refuse_every_malformed_value() {
        for ceiling in [
            MAX_BODY_CEILING,
            REQUEST_TIMEOUT_CEILING,
            MAX_INFLIGHT_CEILING,
            WS_SEND_BUFFER_CEILING,
            WS_MAX_CONNECTIONS_CEILING,
            WS_HEARTBEAT_CEILING,
        ] {
            crate::system::assert_env_ceiling_contract(ceiling);
        }
        assert_eq!(WS_SEND_BUFFER_CEILING.default_value(), 256);
        assert_eq!(WS_HEARTBEAT_CEILING.default_value(), 30);
    }

    #[test]
    fn a_malformed_ws_ceiling_refuses_the_listen_preflight() {
        crate::system::locked_set_var("IPE_WS_HEARTBEAT", "30s");
        let refused = listen_ceilings();
        crate::system::locked_remove_var("IPE_WS_HEARTBEAT");
        assert!(
            refused.is_err_and(|r| r.name() == "IPE_WS_HEARTBEAT"),
            "a malformed per-socket ceiling must refuse Server.listen"
        );
    }

    #[test]
    fn a_queue_ceiling_past_the_tokio_permit_limit_refuses_the_listen_preflight() {
        let past = (tokio::sync::Semaphore::MAX_PERMITS as u64 + 1).to_string();
        let at = tokio::sync::Semaphore::MAX_PERMITS.to_string();
        for name in ["IPE_HTTP_MAX_INFLIGHT", "IPE_WS_SEND_BUFFER"] {
            crate::system::locked_set_var(name, &past);
            let refused = listen_ceilings();
            crate::system::locked_set_var(name, &at);
            let accepted = listen_ceilings();
            crate::system::locked_remove_var(name);
            assert!(
                refused
                    .is_err_and(|r| r.name() == name
                        && r.defect() == crate::system::CeilingDefect::TooLarge),
                "{name} past the permit limit must refuse Server.listen"
            );
            assert!(accepted.is_ok(), "{name} at the permit limit is accepted");
        }
    }

    #[test]
    fn a_malformed_body_ceiling_refuses_the_request() {
        crate::system::locked_set_var("IPE_WEB_MAX_BODY_BYTES", " 1024");
        let refused = max_body();
        crate::system::locked_remove_var("IPE_WEB_MAX_BODY_BYTES");
        assert!(refused.is_err(), "a padded body ceiling must be refused");
        assert_eq!(
            RequestRejection::Unavailable.status_and_reason().0,
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }

    /// Reads the heartbeat ceiling with `IPE_WS_HEARTBEAT` set to `raw`, or unset.
    fn read_heartbeat(raw: Option<&str>) -> Result<u64, crate::system::EnvCeilingRefusal> {
        raw.map_or_else(
            || crate::system::locked_remove_var("IPE_WS_HEARTBEAT"),
            |value| crate::system::locked_set_var("IPE_WS_HEARTBEAT", value),
        );
        let read = WS_HEARTBEAT_CEILING.read::<u64>();
        crate::system::locked_remove_var("IPE_WS_HEARTBEAT");
        read
    }

    #[test]
    fn a_zero_ws_heartbeat_ceiling_refuses() {
        let refused = read_heartbeat(Some("0"));
        assert!(
            refused.is_err_and(|r| r.name() == "IPE_WS_HEARTBEAT"
                && r.defect() == crate::system::CeilingDefect::Zero),
            "a zero heartbeat must be refused, never replaced by the default"
        );
    }

    #[test]
    fn a_non_numeric_ws_heartbeat_ceiling_refuses() {
        let refused = read_heartbeat(Some("not-a-number"));
        assert!(
            refused.is_err_and(|r| r.name() == "IPE_WS_HEARTBEAT"
                && r.defect() == crate::system::CeilingDefect::NotDecimal),
            "a non-numeric heartbeat must be refused, never replaced by the default"
        );
    }

    #[test]
    fn a_valid_ws_heartbeat_ceiling_is_read_and_an_unset_one_takes_the_default() {
        assert_eq!(read_heartbeat(Some("45")).ok(), Some(45));
        assert_eq!(
            read_heartbeat(None).ok(),
            Some(WS_HEARTBEAT_CEILING.default_value())
        );
    }
}

// ─── Ipe.Http.Middleware + Ipe.Http.RateLimit ─────────────────────────────
//
// A Handler is `Fn(ServerRequest) -> IpeTask<E, ServerResponse>`. Each `with*`
// wraps a handler and returns a new one; they chain generically (each output is
// the next's input H), so no concrete `Handler` type is named.

fn header_ci<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn plain_resp(status: i64, body: &str, extra: &[(&str, &str)]) -> ServerResponse {
    let mut headers = HashMap::new();
    for (k, v) in extra {
        set_header_replacing(&mut headers, (*k).to_owned(), (*v).to_owned());
    }
    ServerResponse {
        status,
        body: body.to_string(),
        headers,
        contentType: "text/plain".to_string(),
        cookies: Vec::new(),
    }
}

/// The response header naming the origin a `withCors` response grants.
const CORS_ALLOW_ORIGIN: &str = "access-control-allow-origin";

/// The methods every `withCors` preflight answer allows.
const CORS_PREFLIGHT_METHODS: &str = "GET, POST, PUT, DELETE, OPTIONS";

/// The request headers every `withCors` preflight answer allows.
const CORS_PREFLIGHT_HEADERS: &str = "Content-Type, Authorization";

/// The origin policy of `Middleware.withCors`, parsed once from its list.
enum CorsPolicy {
    /// The list contains `*`: no response depends on `Origin`.
    Any,
    /// Exact serialized origins. An empty entry is dropped, since it never
    /// equals a present non-empty `Origin`, so an empty set refuses every origin.
    Allowlist(Vec<String>),
}

/// A request `Origin` the policy grants.
///
/// The request's own bytes, equal to an allowlist entry; built only by
/// `CorsPolicy::tag`.
struct GrantedOrigin(String);

/// Every CORS header a response from `withCors` carries, as one value.
///
/// `Any` comes only from `CorsPolicy::Any`; `ByOrigin` only from
/// `CorsPolicy::Allowlist`, and every `ByOrigin` response names `Origin` in
/// `Vary`, the refused and the origin-less ones included.
enum CorsTag {
    /// `Access-Control-Allow-Origin: *`; the response does not vary on `Origin`.
    Any,
    /// The response varies on `Origin`; it grants the origin when one is held.
    ByOrigin(Option<GrantedOrigin>),
}

impl CorsPolicy {
    /// The policy of the author's origin list: `*` anywhere grants every origin.
    fn parse(origins: Vec<String>) -> Self {
        if origins.iter().any(|o| o == "*") {
            Self::Any
        } else {
            Self::Allowlist(origins.into_iter().filter(|o| !o.is_empty()).collect())
        }
    }

    /// The CORS tag of a response to a request carrying `origin`.
    fn tag(&self, origin: Option<&str>) -> CorsTag {
        match self {
            Self::Any => CorsTag::Any,
            Self::Allowlist(set) => CorsTag::ByOrigin(
                origin
                    .filter(|o| !o.is_empty() && set.iter().any(|e| e.as_str() == *o))
                    .map(|o| GrantedOrigin(o.to_owned())),
            ),
        }
    }
}

impl CorsTag {
    /// Writes the tag's headers into `resp`.
    ///
    /// The one writer of the CORS headers the middleware owns: a handler-set
    /// `Access-Control-Allow-Origin` in any case is replaced by the grant, or
    /// removed when there is none.
    fn apply(self, resp: &mut ServerResponse) {
        match self {
            Self::Any => set_header_replacing(
                &mut resp.headers,
                CORS_ALLOW_ORIGIN.to_owned(),
                "*".to_owned(),
            ),
            Self::ByOrigin(grant) => {
                merge_vary_origin(&mut resp.headers);
                if let Some(GrantedOrigin(origin)) = grant {
                    set_header_replacing(&mut resp.headers, CORS_ALLOW_ORIGIN.to_owned(), origin);
                } else {
                    resp.headers
                        .retain(|k, _| !k.eq_ignore_ascii_case(CORS_ALLOW_ORIGIN));
                }
            }
        }
    }
}

/// Names `Origin` in the `Vary` of `headers`.
///
/// A handler's `Vary` in any case is merged into one value, never clobbered;
/// one already naming `Origin` or `*` is kept as is.
fn merge_vary_origin(headers: &mut HashMap<String, String>) {
    let vary = match header_values_ci(headers, "Vary") {
        Some(prev)
            if prev.split(',').any(|p| {
                let p = p.trim();
                p == "*" || p.eq_ignore_ascii_case("origin")
            }) =>
        {
            prev
        }
        Some(prev) => format!("{prev}, Origin"),
        None => "Origin".to_owned(),
    };
    set_header_replacing(headers, "Vary".to_owned(), vary);
}

/// Middleware.withCors : List String -> Handler -> Handler.
///
/// Echoes an allowed `Origin` (or `*`), answers every `OPTIONS` as a preflight
/// with 204, and tags every response the handler returns. Under a list of
/// specific origins every response the middleware makes or passes carries
/// `Vary: Origin`; a refused or absent origin gets no
/// `Access-Control-Allow-Origin`, including one the handler set.
pub fn middleware_with_cors<E, H>(origins: Vec<String>, h: H) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let h = h.into_server_handler();
    let policy = CorsPolicy::parse(origins);
    Arc::new(move |req: ServerRequest| {
        let tag = policy.tag(header_ci(&req.headers, "origin"));
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let mut resp = plain_resp(
                204,
                "",
                &[
                    ("access-control-allow-methods", CORS_PREFLIGHT_METHODS),
                    ("access-control-allow-headers", CORS_PREFLIGHT_HEADERS),
                ],
            );
            tag.apply(&mut resp);
            return Box::pin(async move { ok_res(resp) });
        }
        let task = h(req);
        Box::pin(async move {
            match task.await {
                IpeResult::Ok(mut resp) => {
                    tag.apply(&mut resp);
                    ok_res(resp)
                }
                other => other,
            }
        })
    })
}

/// Middleware.withLogging : Handler -> Handler. Logs `method path status Nms`.
pub fn middleware_with_logging<E, H>(h: H) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        let method = req.method.clone();
        let path = req.path.clone();
        let start = std::time::Instant::now();
        let task = h(req);
        Box::pin(async move {
            let result = task.await;
            let status = match &result {
                IpeResult::Ok(r) => r.status,
                IpeResult::Err(_) => 500,
            };
            crate::system::emit_runtime_log(
                "http",
                &format!(
                    "{} {} {} {}ms",
                    method,
                    path,
                    status,
                    start.elapsed().as_millis()
                ),
            );
            result
        })
    })
}

/// Middleware.withBasicAuth : String -> String -> Handler -> Handler. Requires
/// HTTP Basic auth; constant-time credential comparison; 401 otherwise.
pub fn middleware_with_basic_auth<E, H>(user: String, pass: String, h: H) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        use subtle::ConstantTimeEq;
        let expected = format!("Basic {}", base64_encode(format!("{}:{}", user, pass)));
        let got = header_ci(&req.headers, "authorization").unwrap_or("");
        let ok: bool = got.as_bytes().ct_eq(expected.as_bytes()).into();
        if ok {
            h(req)
        } else {
            Box::pin(async move {
                ok_res(plain_resp(
                    401,
                    "Unauthorized",
                    &[("www-authenticate", "Basic realm=\"Ipe\"")],
                ))
            })
        }
    })
}

/// Middleware.withRateLimit : String -> Int -> Int -> Handler -> Handler.
/// Per-(key, client-IP) fixed window; 429 when exceeded.
pub fn middleware_with_rate_limit<E, H>(
    key: String,
    limit: i64,
    window_secs: i64,
    h: H,
) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        if fixed_window_allow(&key, &req.remoteAddr, limit, window_secs) {
            h(req)
        } else {
            Box::pin(async move { ok_res(plain_resp(429, "Too Many Requests", &[])) })
        }
    })
}

/// Whether to trust `X-Forwarded-Proto` (and friends) for TLS-termination
/// detection. Mirrors `build_request`'s existing `IPE_TRUSTED_PROXY` gate for
/// `remoteAddr` (line ~497 above) and `live/mod.rs`'s `trust_proxy_headers()`
/// for the session cookie's `Secure` gate — same env var, same rationale: a
/// client-supplied header must never be trusted by default, an operator opts
/// in only when a real reverse proxy sits in front of this process.
///
/// Snapshotted once (env is stable at process start; same rationale as
/// `csrf_cookie_name`'s production check being re-read per call is fine
/// because it's a plain fn call, but this one backs a per-request hot path so
/// it's cached like `live/mod.rs`'s twin).
fn trust_proxy_headers() -> bool {
    use std::sync::OnceLock;
    static TRUST: OnceLock<bool> = OnceLock::new();
    *TRUST.get_or_init(|| {
        crate::system::read_env_var("IPE_TRUSTED_PROXY")
            .map(|v| !v.is_empty() && v != "0" && v != "false")
            .unwrap_or(false)
    })
}

/// Request-scoped HTTPS detection, parameterised on the trust decision so
/// it's unit-testable without mutating the real (`OnceLock`-cached) process
/// env. Only consulted (via `request_is_https`) when `trust` is true —
/// otherwise a client could forge `X-Forwarded-Proto` to fool the
/// Secure-cookie decision (the same footgun `build_request` already closed
/// for `X-Forwarded-For`). Mirrors `live/mod.rs::request_is_https_with_trust`,
/// adapted to `ServerRequest.headers`'s `HashMap<String, String>` shape
/// (already canonicalised from the axum request at `build_request` time —
/// see `header_ci`) instead of a raw `axum::http::HeaderMap`.
fn request_is_https_with_trust(headers: &HashMap<String, String>, trust: bool) -> bool {
    if !trust {
        return false;
    }
    header_ci(headers, "x-forwarded-proto")
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

/// Request-scoped HTTPS detection: true when THIS request arrived over TLS at
/// a trusted proxy (`X-Forwarded-Proto: https`). See
/// `request_is_https_with_trust` for the testable core.
///
/// MUST be called (and its result captured) BEFORE the `ServerRequest` is
/// moved into the wrapped handler in `middleware_with_csrf` — by the time the
/// response comes back the request is gone, so the boolean has to be
/// snapshotted up front and threaded through as a plain `bool` capture.
fn request_is_https(headers: &HashMap<String, String>) -> bool {
    request_is_https_with_trust(headers, trust_proxy_headers())
}

/// `__Host-` prefix requires Secure + Path=/ + no Domain — mirrors
/// `live/csrf.rs::csrf_cookie_name`'s reasoning, gated on the SAME
/// process-wide [`cookie_secure_floor`] `server_with_cookie` already uses, so
/// naming stays internally consistent with the rest of `server.rs`'s cookie
/// handling.
///
/// This stays process-global (NOT request-scoped) deliberately, same
/// reasoning as the session cookie's `__Host-` name decision
/// (`csrf::cookies_secure()`, `live/mod.rs`): the cookie's IDENTITY must stay
/// stable across a browser session, or the double-submit compare would
/// spuriously fail whenever proxy-scheme detection flips between requests.
/// Only the `Secure` ATTRIBUTE (`csrf_set_cookie_value`) becomes
/// request-scoped.
fn csrf_cookie_name() -> CookieName {
    csrf_cookie_name_with(crate::telemetry::dev_intent_from_env().as_ref())
}

/// [`csrf_cookie_name`] under an explicit dev-intent proof.
fn csrf_cookie_name_with(dev: Option<&crate::telemetry::DevIntent>) -> CookieName {
    let base = if cookie_secure_floor_with(dev) {
        RuntimeCookie::HostCsrf
    } else {
        RuntimeCookie::ServerCsrf
    };
    CookieName::runtime(base, "")
}

/// The process `Secure` floor for an `Ipe.Http.Server` cookie: [`cookie_secure_floor_with`].
fn cookie_secure_floor() -> bool {
    cookie_secure_floor_with(crate::telemetry::dev_intent_from_env().as_ref())
}

/// `Secure` unless `dev` proves a dev-intent binary in a dev posture.
const fn cookie_secure_floor_with(dev: Option<&crate::telemetry::DevIntent>) -> bool {
    dev.is_none()
}

/// The number of random bytes in a CSRF token (256 bits, 64 hex chars).
const CSRF_TOKEN_BYTES: usize = 32;

/// A fresh CSRF token: 256 bits from the OS CSPRNG as 64 lowercase-hex chars.
///
/// Re-exported from `web/csrf.rs` as `mint_token`.
///
/// # Errors
///
/// [`EntropyError`] when the OS random source refuses the draw; there is no
/// fallback token.
pub fn mint_csrf_token() -> Result<String, EntropyError> {
    mint_csrf_token_with(crate::entropy::fill_entropy)
}

/// [`mint_csrf_token`] drawing its bytes from `fill`.
pub(crate) fn mint_csrf_token_with(
    fill: impl FnOnce(&mut [u8]) -> Result<(), EntropyError>,
) -> Result<String, EntropyError> {
    let mut bytes = [0_u8; CSRF_TOKEN_BYTES];
    fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

/// A token "looks valid" if it is the expected 64 lowercase-hex shape — used
/// both to decide whether to reuse a browser cookie token vs mint a fresh one,
/// and as the well-formedness half of `csrf_pair_valid`. Re-exported from
/// `web/csrf.rs` as `token_is_well_formed`.
pub fn csrf_token_well_formed(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Returns `true` iff BOTH tokens pass the well-formedness gate AND compare
/// equal in constant time. The structural check runs before the secret compare —
/// this ordering is standard and does not create a timing side-channel on the
/// secret (the well-formedness predicate observes only length and character
/// class, not the secret value). Fail-closed: any malformed, missing, or
/// mismatched pair returns `false`. Re-exported from `web/csrf.rs`.
pub fn csrf_pair_valid(cookie_tok: &str, header_tok: &str) -> bool {
    use subtle::ConstantTimeEq;
    csrf_token_well_formed(cookie_tok)
        && csrf_token_well_formed(header_tok)
        && bool::from(cookie_tok.as_bytes().ct_eq(header_tok.as_bytes()))
}

/// NOT HttpOnly — client JS must be able to read this to echo it into
/// `X-Csrf-Token` (classic double-submit; still safe against a forging
/// cross-origin page because SOP blocks that page from reading the
/// victim-origin cookie).
///
/// `Secure` is set when EITHER [`cookie_secure_floor`] holds (unconditional
/// floor — every release build and production deploy gets `Secure`, matching
/// `server_with_cookie`'s gate and the session cookie's
/// `csrf::cookies_secure()` half) OR `request_is_https` is true (THIS
/// specific request arrived over TLS at a trusted proxy, opt-in via
/// `IPE_TRUSTED_PROXY` — closes the gap where a dev-intent process
/// fronted by a TLS-terminating proxy would otherwise emit a non-Secure CSRF
/// cookie even though the browser connection was HTTPS). Same OR-gate shape as
/// the session cookie in `web/mod.rs::page_response`.
///
/// `request_is_https` MUST be computed from the ORIGINAL request headers
/// before the request is consumed — see the call site in
/// `middleware_with_csrf`, which captures it into a local `bool` before
/// moving `req` into the wrapped handler `h(req)`. By the time this function
/// runs (after the handler's `Task` resolves), the request itself is gone;
/// only the pre-captured bool survives.
fn csrf_set_cookie_value(token: &str, request_is_https: bool) -> SetCookie {
    let dev = crate::telemetry::dev_intent_from_env();
    csrf_set_cookie_value_with(token, request_is_https, dev.as_ref())
}

/// [`csrf_set_cookie_value`] under an explicit dev-intent proof.
fn csrf_set_cookie_value_with(
    token: &str,
    request_is_https: bool,
    dev: Option<&crate::telemetry::DevIntent>,
) -> SetCookie {
    SetCookie::new(
        &csrf_cookie_name_with(dev),
        &CookieValue::encode(token),
        CookieAttributes {
            path: CookiePath::root(),
            http_only: false,
            same_site: SameSite::Strict,
            secure: cookie_secure_floor_with(dev) || request_is_https,
            max_age_secs: None,
        },
    )
}

/// Middleware.withCsrf : Handler -> Handler. Double-submit-cookie CSRF guard
/// for `Ipe.Http.Server` routes (`__Host-ipe_csrf` cookie, safe methods
/// set/refresh it, unsafe methods require cookie ==
/// `X-Csrf-Token` header via constant-time compare, 403 on any
/// mismatch/missing value).
///
/// Depends on `ServerResponse.cookies` so this middleware's Set-Cookie can
/// never clobber (or be clobbered by) one the wrapped handler sets via
/// `Server.withCookie`.
pub fn middleware_with_csrf<E, H>(h: H) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    middleware_with_csrf_minting(h, mint_csrf_token)
}

/// [`middleware_with_csrf`] minting a missing token through `mint`.
///
/// An unsafe method is judged before any mint. A safe request reuses a
/// well-formed cookie token and mints only without one; a refused mint answers
/// 503 with `Retry-After` and never reaches the handler.
fn middleware_with_csrf_minting<E, H, M>(h: H, mint: M) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
    M: Fn() -> Result<String, EntropyError> + Send + Sync + 'static,
{
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        let safe = matches!(
            req.method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS"
        );
        let cookie_name = csrf_cookie_name();
        let existing = req.cookies.get(cookie_name.text()).cloned();
        if !safe {
            let cookie_tok = existing.as_deref().unwrap_or_default();
            let header_tok = header_ci(&req.headers, "x-csrf-token").unwrap_or("");
            if !csrf_pair_valid(cookie_tok, header_tok) {
                return Box::pin(async move {
                    ok_res(plain_resp(403, "csrf token invalid or missing", &[]))
                });
            }
        }
        let reused = existing.filter(|t| csrf_token_well_formed(t));
        let Ok(token) = reused.map_or_else(&mint, Ok) else {
            return Box::pin(async move {
                ok_res(plain_resp(
                    503,
                    "service unavailable",
                    &[("retry-after", "1")],
                ))
            });
        };
        // Capture the request-scoped TLS signal HERE — before `req` is moved
        // into `h(req)` below: the wrapped handler consumes the request, so
        // nothing is left to inspect once `task` is awaited.
        let is_https = request_is_https(&req.headers);
        let task = h(req);
        Box::pin(async move {
            match task.await {
                IpeResult::Ok(mut resp) => {
                    resp.cookies.push(csrf_set_cookie_value(&token, is_https));
                    IpeResult::Ok(resp)
                }
                other => other,
            }
        })
    })
}

/// How often (in calls) the rate-limit maps run their full-map expiry sweep.
/// The `retain` is O(n); running it every call lets an attacker who supplies many
/// distinct client keys (trusted-proxy mode, attacker-controlled X-Forwarded-For)
/// turn each request into a full-map scan (CPU amplification). Amortizing the
/// sweep to every RL_SWEEP_EVERY calls bounds that to O(n / RL_SWEEP_EVERY) per
/// request while still reclaiming expired entries (memory stays bounded).
const RL_SWEEP_EVERY: u64 = 256;

fn unix_secs_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

struct WindowEntry {
    start: f64,
    count: i64,
}

fn fixed_window_allow(key: &str, client: &str, limit: i64, window_secs: i64) -> bool {
    static W: OnceLock<Mutex<HashMap<(String, String), WindowEntry>>> = OnceLock::new();
    static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = unix_secs_f64();
    let window = window_secs.max(1) as f64;
    let mut m = W
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Evict fully-expired entries so the map can't grow without bound (distinct
    // clients/keys would otherwise accumulate forever → memory-DoS). The O(n) scan
    // is AMORTIZED to every RL_SWEEP_EVERY calls so an attacker can't force a
    // full-map scan per request (CPU amplification). An expired entry resets to
    // count 0 on access anyway, so a lingering one between sweeps is
    // behaviour-preserving for the surviving (live) entries.
    if TICK
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(RL_SWEEP_EVERY)
    {
        m.retain(|_, ent| now - ent.start < window);
    }
    let e = m
        .entry((key.to_string(), client.to_string()))
        .or_insert(WindowEntry {
            start: now,
            count: 0,
        });
    if now - e.start >= window {
        e.start = now;
        e.count = 0;
    }
    if e.count < limit.max(0) {
        e.count += 1;
        true
    } else {
        false
    }
}

struct Bucket {
    tokens: f64,
    last: f64,
}

/// RateLimit.allow : String -> String -> Int -> Int -> Bool — token bucket per
/// (name, key); capacity tokens, refilled `refill_per_sec`. True if a token was
/// consumed.
pub fn rate_limit_allow(name: String, key: String, capacity: i64, refill_per_sec: i64) -> bool {
    static B: OnceLock<Mutex<HashMap<(String, String), Bucket>>> = OnceLock::new();
    static TICK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let cap = capacity.max(0) as f64;
    let now = unix_secs_f64();
    let refill = refill_per_sec.max(0) as f64;
    let mut m = B
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    // Evict an entry if EITHER it has refilled back to full (indistinguishable
    // from a fresh bucket) OR it has been idle longer than RL_IDLE_TTL. The
    // idle bound is refill-INDEPENDENT: with refill_per_sec == 0 a partially-drained
    // bucket never refills to full, so the refill-only predicate would retain it
    // forever and the map grows unbounded across distinct (name, key) pairs
    // (memory-DoS). The O(n) scan is AMORTIZED to every RL_SWEEP_EVERY calls so an
    // attacker supplying many distinct keys can't force a full-map scan per request
    // (CPU amplification). Either way the current entry is re-created below if swept.
    const RL_IDLE_TTL: f64 = 3600.0; // 1 h with no access → reclaim
    if TICK
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(RL_SWEEP_EVERY)
    {
        m.retain(|_, bk| {
            let refilled = (bk.tokens + (now - bk.last) * refill).min(cap);
            refilled < cap && (now - bk.last) < RL_IDLE_TTL
        });
    }
    let b = m.entry((name, key)).or_insert(Bucket {
        tokens: cap,
        last: now,
    });
    b.tokens = (b.tokens + (now - b.last) * refill).min(cap);
    b.last = now;
    if b.tokens >= 1.0 {
        b.tokens -= 1.0;
        true
    } else {
        false
    }
}

#[cfg(test)]
#[cfg(feature = "jwt")]
mod revocation_env_tests {
    use super::*;

    const SECRET: &str = "a-test-secret-of-32-bytes-padding";
    const ENV: &str = "IPE_AUTH_REVOCATION";

    fn bearer_cfg() -> AuthConfig {
        server_auth_config(
            crate::secret::secret_from_string(SECRET.to_string()),
            TokenSource::BearerHeader,
        )
    }

    fn token_for(jti: &str) -> String {
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        let key = jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes());
        let claims = serde_json::json!({
            "sub": "env-revocation-user",
            "jti": jti,
            "exp": 9_999_999_999i64,
        });
        jsonwebtoken::encode(&header, &claims, &key).unwrap_or_default()
    }

    /// The status the authed route answers for a bearer token carrying `jti`,
    /// with the route built while `IPE_AUTH_REVOCATION` is `env`.
    async fn status_with_env(cfg: AuthConfig, env: &str, jti: &str) -> i64 {
        crate::system::locked_set_var(ENV, env);
        let route = server_get_authed::<String, _>("/me".to_string(), cfg, |_req, principal| {
            let subject = crate::principal::principal_subject(principal);
            Box::pin(std::future::ready(ok_res(server_text(subject))))
        });
        crate::system::locked_remove_var(ENV);
        let RouteTarget::Handler(handler) = route.target else {
            return 500;
        };
        let req = ServerRequest {
            method: "GET".to_string(),
            path: "/me".to_string(),
            body: String::new(),
            headers: [(
                "authorization".to_string(),
                format!("Bearer {}", token_for(jti)),
            )]
            .into_iter()
            .collect(),
            params: HashMap::new(),
            query: HashMap::new(),
            cookies: HashMap::new(),
            remoteAddr: String::new(),
        };
        dispatch(&handler, req)
            .await
            .0
            .map_or(500, |resp| resp.status)
    }

    #[tokio::test]
    async fn revocation_env_off_cannot_disarm_server_store() {
        let jti = "env-off-cannot-disarm-jti-001";
        assert!(crate::revocation::revoke_session(jti.to_string(), i64::MAX / 2).is_ok());
        let armed = server_with_revocation(1, bearer_cfg());
        assert_eq!(
            status_with_env(armed, "off", jti).await,
            401,
            "the env must not switch off a gate written in code"
        );
    }

    #[tokio::test]
    async fn revocation_env_store_arms_server_gate() {
        let revoked = "env-store-arms-revoked-jti-001";
        let active = "env-store-arms-active-jti-001";
        assert!(crate::revocation::revoke_session(revoked.to_string(), i64::MAX / 2).is_ok());
        assert_eq!(
            status_with_env(bearer_cfg(), "off", revoked).await,
            200,
            "without the env the unarmed route does not consult the store"
        );
        assert_eq!(
            status_with_env(bearer_cfg(), "store", revoked).await,
            401,
            "the env arms the gate on a route built without one"
        );
        assert_eq!(
            status_with_env(bearer_cfg(), "store", active).await,
            200,
            "an armed gate lets an active session through"
        );
    }

    #[tokio::test]
    async fn revocation_env_unknown_value_arms_server_gate() {
        let jti = "env-unknown-arms-jti-001";
        assert!(crate::revocation::revoke_session(jti.to_string(), i64::MAX / 2).is_ok());
        assert_eq!(
            status_with_env(bearer_cfg(), "stroe", jti).await,
            401,
            "a value the runtime cannot parse is never read as the permissive one"
        );
    }

    /// A present `IPE_AUTH_REVOCATION` that names no mode refuses the listener
    /// before it binds, naming the variable.
    #[tokio::test]
    async fn listen_refuses_an_unknown_revocation_mode() {
        for raw in ["stroe", "on", "2"] {
            crate::system::locked_set_var(ENV, raw);
            // A listener that got past the refusal would bind and serve forever;
            // the timeout turns that regression into a failure instead of a hang.
            let listened: Result<IpeResult<crate::IpeError, ()>, _> = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                server_listen(0, Vec::new()),
            )
            .await;
            crate::system::locked_remove_var(ENV);
            let refusal = match listened {
                Ok(IpeResult::Err(error)) => Some(error),
                Ok(IpeResult::Ok(())) | Err(_) => None,
            };
            assert!(
                refusal.as_ref().is_some_and(|error| {
                    crate::ipe_error_kind(error.clone()) == crate::IpeErrorKind::InvalidInput
                        && crate::ipe_error_message(error.clone())
                            .starts_with("Server.listen: IPE_AUTH_REVOCATION must be")
                }),
                "IPE_AUTH_REVOCATION={raw:?} must refuse the listener as invalid input \
                 naming the variable, got {refusal:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::ready;

    #[tokio::test]
    async fn a_request_stuck_past_the_grace_still_stops_within_its_bound() {
        use tokio::io::AsyncWriteExt as _;
        let grace = std::time::Duration::from_millis(200);
        let (armed, signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            grace,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let host = RecordedHost::record(crate::app_config::ListenHost::Loopback(
            crate::app_config::LoopbackIp::DEFAULT,
        ));
        let app = bind_app_listener("test", host, 0)
            .await
            .expect("a loopback port binds");
        let port = app.listener.local_addr().expect("a bound port").port();
        let entered = Arc::new(tokio::sync::Notify::new());
        let entering = Arc::clone(&entered);
        let router = axum::Router::new().route(
            "/stuck",
            axum::routing::get(move || {
                let entering = Arc::clone(&entering);
                async move {
                    entering.notify_one();
                    std::future::pending::<&'static str>().await
                }
            }),
        );
        let served = tokio::spawn(serve_app(app, router, armed));
        let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the app accepts");
        let request = format!("GET /stuck HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("the request is sent");
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .expect("the handler runs");
        let signalled = std::time::Instant::now();
        assert!(signals.send(shutdown::Signal::Terminate).await.is_ok());
        #[cfg(feature = "db")]
        let close = shutdown::POOLS_CLOSE_BOUND;
        #[cfg(not(feature = "db"))]
        let close = std::time::Duration::ZERO;
        let bound = grace + close + std::time::Duration::from_secs(2);
        let stopped = tokio::time::timeout(bound, served)
            .await
            .expect("a stuck request never holds the stop past its bound");
        assert!(matches!(stopped, Ok(Ok(shutdown::Stopped { .. }))));
        assert!(signalled.elapsed() < bound);
        drop(client);
    }

    #[tokio::test]
    async fn a_site_that_drains_first_waits_for_its_sibling_before_closing_pools() {
        use tokio::io::AsyncWriteExt as _;
        let budget = std::time::Duration::from_secs(5);
        let (idle_site, busy_site, signals) =
            shutdown::tests::armed_pair(std::time::Duration::from_secs(30));
        let bind = || {
            bind_app_listener(
                "test",
                RecordedHost::record(crate::app_config::ListenHost::Loopback(
                    crate::app_config::LoopbackIp::DEFAULT,
                )),
                0,
            )
        };
        let idle_app = bind().await.expect("a loopback port binds");
        let busy_app = bind().await.expect("a loopback port binds");
        let port = busy_app.listener.local_addr().expect("a bound port").port();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let (entering, released) = (Arc::clone(&entered), Arc::clone(&release));
        let router = axum::Router::new().route(
            "/held",
            axum::routing::get(move || {
                let (entering, released) = (Arc::clone(&entering), Arc::clone(&released));
                async move {
                    entering.notify_one();
                    released.notified().await;
                    "done"
                }
            }),
        );
        let idle = tokio::spawn(serve_app(idle_app, axum::Router::new(), idle_site));
        let busy = tokio::spawn(serve_app(busy_app, router, busy_site));
        let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the app accepts");
        let request =
            format!("GET /held HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("the request is sent");
        tokio::time::timeout(budget, entered.notified())
            .await
            .expect("the handler runs");
        assert!(signals.send(shutdown::Signal::Terminate).await.is_ok());
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !idle.is_finished(),
            "an idle site closes the shared pools while a sibling still serves a request"
        );
        release.notify_one();
        let busy = tokio::time::timeout(budget, busy)
            .await
            .expect("the busy site stops");
        assert!(matches!(busy, Ok(Ok(shutdown::Stopped { .. }))));
        let idle = tokio::time::timeout(budget, idle)
            .await
            .expect("the idle site stops");
        assert!(matches!(idle, Ok(Ok(shutdown::Stopped { .. }))));
        drop(client);
    }

    /// Sets its flag when the future holding it is dropped.
    struct DropFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// A router stand-in that counts its calls and flags when a call's
    /// future first runs.
    fn probed(
        calls: &Arc<std::sync::atomic::AtomicUsize>,
        polled: &Arc<std::sync::atomic::AtomicBool>,
    ) -> impl tower::Service<
        axum::extract::Request,
        Response = axum::response::Response,
        Error = std::convert::Infallible,
        Future = impl std::future::Future<
            Output = Result<axum::response::Response, std::convert::Infallible>,
        > + Send
                 + 'static,
    > {
        use axum::response::IntoResponse as _;
        let (calls, polled) = (Arc::clone(calls), Arc::clone(polled));
        tower::service_fn(move |_request: axum::extract::Request| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let polled = Arc::clone(&polled);
            async move {
                polled.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, std::convert::Infallible>(axum::http::StatusCode::OK.into_response())
            }
        })
    }

    /// One empty request through `svc`, answered.
    async fn answer<S>(svc: &mut S) -> axum::response::Response
    where
        S: tower::Service<
                axum::extract::Request,
                Response = axum::response::Response,
                Error = std::convert::Infallible,
            > + Send,
        S::Future: Send,
    {
        use tower::ServiceExt as _;
        let request = axum::extract::Request::new(axum::body::Body::empty());
        let ready = match svc.ready().await {
            Ok(ready) => ready,
            Err(never) => match never {},
        };
        match ready.call(request).await {
            Ok(response) => response,
            Err(never) => match never {},
        }
    }

    /// Whether `response` is the shutdown's 503 that closes its connection.
    fn is_work_refusal(response: &axum::response::Response) -> bool {
        response.status() == axum::http::StatusCode::SERVICE_UNAVAILABLE
            && response
                .headers()
                .get(axum::http::header::CONNECTION)
                .is_some_and(|value| value.as_bytes() == b"close")
    }

    #[tokio::test]
    async fn a_request_after_the_close_never_runs_its_handler() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tower::Layer as _;
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let polled = Arc::new(AtomicBool::new(false));
        let mut svc = WorkLayer {
            count: armed.work_count(),
        }
        .layer(probed(&calls, &polled));
        let served = answer(&mut svc).await;
        assert_eq!(served.status(), axum::http::StatusCode::OK);
        assert!(
            polled.load(Ordering::SeqCst),
            "a serving owner runs the handler"
        );
        let _settled = armed.cancel_work().await;
        // Each request races a ready handler against its born-cancelled
        // guard; only the biased cancel arm wins every time.
        for _ in 0..64 {
            polled.store(false, Ordering::SeqCst);
            let refused = answer(&mut svc).await;
            assert!(
                is_work_refusal(&refused),
                "a closed owner answers 503 and closes"
            );
            assert!(
                !polled.load(Ordering::SeqCst),
                "a request after the close never runs its handler"
            );
        }
    }

    #[tokio::test]
    async fn a_request_past_the_work_ceiling_is_refused_before_its_handler() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use tower::Layer as _;
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let polled = Arc::new(AtomicBool::new(false));
        let mut svc = WorkLayer {
            count: armed.work_count(),
        }
        .layer(probed(&calls, &polled));
        armed.force_work_state(shutdown::WORK_CEILING);
        let refused = answer(&mut svc).await;
        assert!(
            is_work_refusal(&refused),
            "a full owner answers 503 and closes"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the handler is never called"
        );
        assert!(!polled.load(Ordering::SeqCst));
        assert_eq!(armed.work_in_flight(), shutdown::WORK_CEILING);
    }

    #[tokio::test]
    async fn an_unsignalled_serve_error_leaves_the_shared_owner_serving() {
        let budget = std::time::Duration::from_secs(1);
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::from_secs(30),
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let count = armed.work_count();
        let mut sibling = count.guard().expect("a serving owner counts work");
        let failing = ready(Err(std::io::Error::other("accept failed")));
        let served = serve_until_drained(failing, &armed).await;
        let stopped = tokio::time::timeout(budget, stop_after_serve(&armed, served))
            .await
            .expect("an unsignalled serve error returns at once");
        assert!(stopped.is_err_and(|e| e.to_string() == "accept failed"));
        assert!(!armed.is_draining(), "the shared owner still serves");
        assert_eq!(armed.live_count(), 0, "the failed site holds nothing");
        let cancelled =
            tokio::time::timeout(std::time::Duration::from_millis(50), sibling.cancelled()).await;
        assert!(cancelled.is_err(), "a sibling's work is not cancelled");
        let _next = count.guard().expect("new work is still admitted");
        assert_eq!(armed.work_in_flight(), 2, "new work is still counted");
        let ended = tokio::time::timeout(budget, stop_after_serve(&armed, Ok(())))
            .await
            .expect("an unsignalled clean end returns at once");
        assert!(ended.is_err(), "a serve that ends unsignalled is no stop");
        assert!(!armed.is_draining());
    }

    #[tokio::test]
    async fn a_signalled_serve_error_still_tears_down_before_it_returns() {
        let budget = std::time::Duration::from_secs(5);
        let (armed, signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let mut held = armed
            .work_count()
            .guard()
            .expect("a serving owner counts work");
        let mut drain = armed.drain();
        assert!(signals.send(shutdown::Signal::Terminate).await.is_ok());
        tokio::time::timeout(budget, drain.wait())
            .await
            .expect("the signal drains the owner");
        let failing = ready(Err(std::io::Error::other("accept failed")));
        let served = serve_until_drained(failing, &armed).await;
        let stopped = tokio::time::timeout(budget, stop_after_serve(&armed, served))
            .await
            .expect("the teardown ends under its bound");
        assert!(stopped.is_err_and(|e| e.to_string() == "accept failed"));
        tokio::time::timeout(std::time::Duration::from_millis(1), held.cancelled())
            .await
            .expect("the teardown cancelled the counted work");
        assert_eq!(armed.live_count(), 0, "the site released its live hold");
    }

    #[tokio::test]
    async fn a_request_running_past_the_grace_is_cancelled_before_the_stop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let budget = std::time::Duration::from_secs(5);
        let (armed, signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let host = RecordedHost::record(crate::app_config::ListenHost::Loopback(
            crate::app_config::LoopbackIp::DEFAULT,
        ));
        let app = bind_app_listener("test", host, 0)
            .await
            .expect("a loopback port binds");
        let port = app.listener.local_addr().expect("a bound port").port();
        let entered = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let (entering, finishing, dropping) = (
            Arc::clone(&entered),
            Arc::clone(&finished),
            Arc::clone(&dropped),
        );
        let router = axum::Router::new().route(
            "/slow",
            axum::routing::get(move || {
                let (entering, finishing) = (Arc::clone(&entering), Arc::clone(&finishing));
                let sentinel = DropFlag(Arc::clone(&dropping));
                async move {
                    let _sentinel = sentinel;
                    entering.notify_one();
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    finishing.store(true, Ordering::SeqCst);
                    "done"
                }
            }),
        );
        let served = tokio::spawn(serve_app(app, router, armed));
        let mut client = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the app accepts");
        let request = format!("GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n");
        client
            .write_all(request.as_bytes())
            .await
            .expect("the request is sent");
        tokio::time::timeout(budget, entered.notified())
            .await
            .expect("the handler runs");
        assert!(signals.send(shutdown::Signal::Terminate).await.is_ok());
        let stopped = tokio::time::timeout(budget, served)
            .await
            .expect("the app stops");
        assert!(matches!(stopped, Ok(Ok(shutdown::Stopped { .. }))));
        assert!(
            dropped.load(Ordering::SeqCst),
            "the handler's future is dropped before the pools close"
        );
        let mut answer = Vec::new();
        tokio::time::timeout(budget, client.read_to_end(&mut answer))
            .await
            .expect("the cancelled request is answered and closed")
            .expect("the answer reads");
        let answer = String::from_utf8(answer).expect("the answer is UTF-8");
        assert!(answer.starts_with("HTTP/1.1 503"), "got {answer:?}");
        assert!(answer.to_ascii_lowercase().contains("connection: close"));
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        assert!(
            !finished.load(Ordering::SeqCst),
            "a request past the grace never runs on after the stop"
        );
    }

    /// `Ipe.Http.Server` resolves through the shared resolver under its own
    /// operator var: an operator value wins over the source port, and a
    /// supervisor relocation wins over both.
    #[test]
    fn ipe_server_port_resolves_operator_over_source_under_relocation() {
        let key = crate::env_registry::listen::SERVER_PORT;
        let lookup = |value: Option<&str>| {
            value.map_or(Err(std::env::VarError::NotPresent), |v| Ok(v.to_owned()))
        };
        let try_resolve = |relocation: Option<&str>, operator: Option<&str>| {
            crate::system::resolve_listen_port(
                crate::env_registry::listen::LISTEN_PORT_RELOCATION.parse(lookup(relocation)),
                (key.name(), key.parse(lookup(operator))),
                crate::system::SourcePort::parse(8000).expect("8000 is a port"),
            )
        };
        let resolve = |relocation: Option<&str>, operator: Option<&str>| {
            try_resolve(relocation, operator).expect("well-formed layers resolve")
        };
        assert_eq!(resolve(None, Some("9123")).port.get(), 9123);
        assert_eq!(resolve(Some("9100"), Some("9123")).port.get(), 9100);
        assert!(
            try_resolve(None, Some("0")).is_err_and(|r| r.name() == "IPE_SERVER_PORT"),
            "a malformed operator port refuses, never falls back"
        );
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 8000));
        let dev = crate::telemetry::BuildPosture::Development;
        let advice = |r: crate::system::ResolvedPort| {
            crate::ipe_error_message(r.bind_refusal_for(dev, "Server.listen", addr, &in_use))
        };
        assert!(advice(resolve(None, None)).contains("IPE_SERVER_PORT=8123 ipe dev run"));
        assert!(!advice(resolve(Some("9100"), None)).contains("IPE_SERVER_PORT"));
    }

    /// A port another socket holds refuses `Server.listen` as a typed
    /// `Conflict` naming `IPE_SERVER_PORT`, never the `Unexpected` catch-all,
    /// and a release binary's fix line names no `ipe` verb.
    #[tokio::test]
    async fn listen_on_a_held_port_is_a_typed_conflict() {
        let held = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("bind an ephemeral loopback port to hold");
        let port = held.local_addr().expect("the held port's address").port();
        crate::system::locked_set_var("IPE_HTTP_BIND", "127.0.0.1");
        // A listener that bound anyway would serve forever; the timeout turns
        // that regression into a failure instead of a hang.
        let listened: Result<IpeResult<crate::IpeError, ()>, _> = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_listen(i64::from(port), Vec::new()),
        )
        .await;
        crate::system::locked_remove_var("IPE_HTTP_BIND");
        drop(held);
        assert!(
            matches!(&listened, Ok(IpeResult::Err(_))),
            "a held port must refuse the listener: {listened:?}"
        );
        let Ok(IpeResult::Err(error)) = listened else {
            return;
        };
        assert_eq!(
            crate::ipe_error_kind(error.clone()),
            crate::IpeErrorKind::Conflict
        );
        let text = error.to_ipe_string();
        assert!(
            text.starts_with(&format!("Conflict: port {port} is already in use")),
            "{text}"
        );
        assert!(text.contains("IPE_SERVER_PORT=8123"), "{text}");
        assert!(
            cfg!(feature = "dev-posture") || !text.contains("ipe dev"),
            "a release binary must not advise an `ipe` verb: {text}"
        );
    }

    /// Each operator-fixable bind failure is its own error kind with a fix
    /// line; a release binary's fix line names the program, not `ipe dev run`.
    #[test]
    fn bind_refusals_are_typed_and_release_advice_names_no_dev_verb() {
        use crate::telemetry::BuildPosture;
        use std::io::ErrorKind;
        let resolved = crate::system::resolve_listen_port(
            Ok(None),
            (crate::env_registry::listen::SERVER_PORT.name(), Ok(None)),
            crate::system::SourcePort::parse(80).expect("80 is a port"),
        )
        .expect("no env layer is set");
        let addr = std::net::SocketAddr::from(([10, 255, 255, 1], 80));
        let refusal = |posture: BuildPosture, kind: ErrorKind| {
            let error = resolved.bind_refusal_for(
                posture,
                "Server.listen",
                addr,
                &std::io::Error::from(kind),
            );
            (
                crate::ipe_error_kind(error.clone()),
                crate::ipe_error_message(error),
            )
        };
        for (kind, expected, fix) in [
            (
                ErrorKind::AddrInUse,
                crate::IpeErrorKind::Conflict,
                "IPE_SERVER_PORT=8123",
            ),
            (
                ErrorKind::PermissionDenied,
                crate::IpeErrorKind::PermissionDenied,
                "IPE_SERVER_PORT=8123",
            ),
            (
                ErrorKind::AddrNotAvailable,
                crate::IpeErrorKind::InvalidInput,
                "IPE_HTTP_BIND=127.0.0.1",
            ),
        ] {
            let (release_kind, release) = refusal(BuildPosture::Release, kind);
            assert_eq!(release_kind, expected, "{kind:?}: {release}");
            assert!(
                release.contains(&format!("{fix} ./<program>")) && !release.contains("ipe dev"),
                "{kind:?}: {release}"
            );
            let (dev_kind, dev) = refusal(BuildPosture::Development, kind);
            assert_eq!(dev_kind, expected, "{kind:?}: {dev}");
            assert!(
                dev.contains(&format!("{fix} ipe dev run")),
                "{kind:?}: {dev}"
            );
        }
        let (_, privileged) = refusal(BuildPosture::Release, ErrorKind::PermissionDenied);
        assert!(privileged.contains("below 1024"), "{privileged}");
        let (_, not_local) = refusal(BuildPosture::Release, ErrorKind::AddrNotAvailable);
        assert!(
            not_local.starts_with("10.255.255.1 is not an address of this host"),
            "{not_local}"
        );
        let (other_kind, other) = refusal(BuildPosture::Release, ErrorKind::ConnectionReset);
        assert_eq!(other_kind, crate::IpeErrorKind::Io, "{other}");
        assert!(
            other.starts_with("Server.listen: bind 10.255.255.1:80: "),
            "{other}"
        );
    }

    fn handler_route(method: &str, path: &str) -> ServerRoute {
        ServerRoute {
            method: method.to_string(),
            path: path.to_string(),
            target: RouteTarget::Handler(name_echo()),
        }
    }

    /// The listen-time conflict verdict on handlers `(METHOD, path)`, and
    /// whether the router accepts every insert of the same set.
    #[allow(clippy::expect_used)] // test: every path and method in the tables parses
    fn conflict_and_router(set: &[(&str, &str)]) -> (Option<String>, bool) {
        let routes = || {
            parse_routes(set.iter().map(|(m, p)| handler_route(m, p)).collect())
                .expect("the table's routes parse")
        };
        let verdict = endpoint_conflict(&routes()).map(|r| r.to_string());
        let inserted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut app = axum::Router::new();
            for route in routes() {
                if let ParsedTarget::Handler(method, pattern, h) = route.target {
                    let path = pattern.router_path().to_owned();
                    app = app.route(&path, method_router(method, pattern, h));
                }
            }
        }))
        .is_ok();
        (verdict, inserted)
    }

    /// Prove the refusals: two handlers of one shape with an overlapping
    /// method are refused before any insert, whatever their parameter names
    /// or literal spellings. The router refuses two filtered methods itself,
    /// but registers `ANY` beside a filtered method as a method fallback, so
    /// for those sets the check is the one gate that keeps a handler from
    /// silently shadowing part of another.
    #[test]
    fn handlers_of_one_shape_and_method_conflict() {
        for (set, router_refuses) in [
            ([("GET", "/a/:x"), ("GET", "/a/:y")], true),
            ([("GET", "/café"), ("GET", "/caf%C3%A9")], true),
            ([("GET", "/api"), ("GET", "/%61pi")], true),
            ([("get", "/a"), ("GET", "/a")], true),
            ([("ANY", "/hook"), ("POST", "/hook")], false),
            ([("PATCH", "/x/:id"), ("ANY", "/x/:key")], false),
        ] {
            let (verdict, inserted) = conflict_and_router(&set);
            assert!(
                verdict
                    .as_deref()
                    .is_some_and(|m| m.contains("conflicts with")),
                "{set:?}"
            );
            assert_eq!(inserted, !router_refuses, "{set:?}");
        }
    }

    /// Every handler set the check accepts registers without a router
    /// conflict: a trailing slash, a literal beside a parameter, and two
    /// methods on one shape are all distinct.
    #[test]
    fn handlers_the_check_accepts_all_register() {
        for set in [
            vec![("GET", "/a/"), ("GET", "/a")],
            vec![("GET", "/a/:x"), ("POST", "/a/:y")],
            vec![("GET", "/a/b"), ("GET", "/a/:x")],
            vec![("GET", "/a/:x"), ("GET", "/a/:y/b"), ("GET", "/a/:z/:w")],
            vec![
                ("GET", "/r"),
                ("HEAD", "/r"),
                ("PATCH", "/r"),
                ("DELETE", "/r"),
            ],
            vec![
                ("GET", "/"),
                ("GET", "/:x"),
                ("GET", "/a//b"),
                ("GET", "/a%2Fb"),
            ],
            vec![
                ("GET", "/api/users"),
                ("GET", "/api/posts"),
                ("POST", "/api/users"),
                ("DELETE", "/api/users/:id"),
            ],
        ] {
            assert_eq!(conflict_and_router(&set), (None, true), "{set:?}");
        }
    }

    /// Prove the refusal: a handler whose method is no HTTP method is refused
    /// at parse with the endpoint named, never served for every method.
    #[test]
    fn a_handler_naming_no_http_method_is_refused() {
        for (method, path) in [("FETCH", "/x"), ("", "/x"), ("MOUNT", "/x")] {
            let refused = parse_routes(vec![handler_route(method, path)]).err();
            assert!(
                refused
                    .as_ref()
                    .is_some_and(|r| r.cause == RouteCause::Method
                        && r.endpoint == quoted_endpoint(&method.to_uppercase(), path)),
                "{method:?}"
            );
            assert!(
                refused.is_some_and(|r| r.to_string().contains("names no HTTP method")),
                "{method:?}"
            );
        }
        assert!(EndpointMethod::parse("patch") == Some(EndpointMethod::Patch));
    }

    /// A handler serves its own method only: a `PATCH` handler answers
    /// `PATCH` and refuses `GET` with 405.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed routes parse and fixed requests build
    async fn a_handler_serves_its_own_method_only() {
        use tower::ServiceExt;
        let mut app = axum::Router::new();
        for route in parse_routes(vec![handler_route("PATCH", "/r")]).expect("parses") {
            if let ParsedTarget::Handler(method, pattern, h) = route.target {
                let path = pattern.router_path().to_owned();
                app = app.route(&path, method_router(method, pattern, h));
            }
        }
        let app = behind_listener(app);
        for (method, status) in [
            ("PATCH", axum::http::StatusCode::OK),
            ("GET", axum::http::StatusCode::METHOD_NOT_ALLOWED),
            ("POST", axum::http::StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let wire = axum::http::Request::builder()
                .method(method)
                .uri("/r")
                .body(axum::body::Body::empty())
                .expect("test request builds");
            let resp = match app.clone().oneshot(wire).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            assert_eq!(resp.status(), status, "{method}");
        }
    }

    /// Prove the refusal at listen: a conflicting handler set returns a typed
    /// `Conflict` before binding, never the `Unexpected` catch-all.
    #[tokio::test]
    async fn listen_refuses_a_conflicting_handler_set_before_bind() {
        let routes = vec![handler_route("GET", "/a/:x"), handler_route("GET", "/a/:y")];
        let listened: IpeResult<crate::IpeError, ()> =
            tokio::time::timeout(std::time::Duration::from_secs(10), server_listen(0, routes))
                .await
                .expect("a refused route set must return before binding, not serve");
        let IpeResult::Err(error) = listened else {
            assert!(
                matches!(listened, IpeResult::Err(_)),
                "a conflict must refuse"
            );
            return;
        };
        assert_eq!(
            crate::ipe_error_kind(error.clone()),
            crate::IpeErrorKind::Conflict
        );
        let msg = crate::ipe_error_message(error);
        assert!(
            msg.starts_with("Server.listen: endpoint `GET /a/:x` conflicts with `GET /a/:y`"),
            "{msg}"
        );
    }

    /// A handler that answers with its `name` parameter.
    fn name_echo() -> ErasedHandler {
        Arc::new(|req: ServerRequest| {
            let resp = server_text(req.params.get("name").cloned().unwrap_or_default());
            Box::pin(async move { Ok(resp) })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<ServerResponse, String>> + Send>,
                >
        })
    }

    fn get_route(path: &str) -> ServerRoute {
        ServerRoute {
            method: "GET".to_string(),
            path: path.to_string(),
            target: RouteTarget::Handler(name_echo()),
        }
    }

    /// Prove the refusals at listen: every endpoint path is parsed before any
    /// insert or bind, so a malformed one refuses the route set with the
    /// endpoint and the cause named, and never reaches the router.
    #[tokio::test]
    async fn listen_refuses_a_malformed_endpoint_path_before_bind() {
        let over_cap = format!(
            "/{}",
            "a".repeat(crate::encoding::MAX_URL_COMPONENT_LEN.get())
        );
        let too_many: String = (0..=crate::encoding::MAX_SERVER_PARAMS)
            .map(|i| format!("/:p{i}"))
            .collect();
        let malformed = crate::IpeErrorKind::InvalidInput;
        let ceiling = crate::IpeErrorKind::LimitExceeded;
        for (bad, cause, kind) in [
            ("/:", "has no name", malformed),
            ("/:a/:a", "appears twice", malformed),
            ("/*rest", "catch-all", malformed),
            ("/a/%zz", "malformed percent-escape", malformed),
            ("/a:b", "byte 1", malformed),
            ("api", "starts with `/`", malformed),
            (over_cap.as_str(), "component longer than", ceiling),
            (too_many.as_str(), "parameters", ceiling),
        ] {
            let routes = vec![get_route("/ok"), get_route(bad)];
            assert!(
                parse_routes(routes.clone())
                    .is_err_and(|r| r.endpoint == quoted_endpoint("GET", bad)),
                "{cause}: the refusal names the endpoint"
            );
            // A listener that got past the refusal would bind and serve
            // forever; the timeout turns that regression into a failure.
            let listened: IpeResult<crate::IpeError, ()> =
                tokio::time::timeout(std::time::Duration::from_secs(10), server_listen(0, routes))
                    .await
                    .expect("a refused route set must return before binding, not serve");
            assert!(
                matches!(listened, IpeResult::Err(_)),
                "{cause}: a malformed path must refuse the listener"
            );
            let IpeResult::Err(error) = listened else {
                return;
            };
            assert_eq!(crate::ipe_error_kind(error.clone()), kind, "{cause}");
            let msg = crate::ipe_error_message(error);
            assert!(
                msg.starts_with("Server.listen: endpoint `GET ")
                    && msg.contains("is not a well-formed route path")
                    && msg.contains(cause),
                "{msg:.200}"
            );
            assert!(msg.len() < 400, "the error quotes a bounded excerpt");
        }
    }

    /// Prove the refusals: a mount prefix that is not a mount base is refused
    /// at listen, before any bind, naming the mount.
    #[test]
    fn a_malformed_mount_prefix_is_refused_at_listen() {
        for prefix in [
            "/a?b",
            "/a#b",
            "/a/%zz",
            "/a%62",
            "/a:b",
            "/:id/:id",
            "/f/*rest",
            "/caf\u{e9}",
            "/static/",
            "static",
            "/a//b",
            "/a/..",
        ] {
            let refused = parse_routes(vec![server_static(prefix.to_owned(), "dir".to_owned())]);
            let Err(refusal) = refused else {
                assert!(refused.is_err(), "{prefix:?} must be refused");
                return;
            };
            let msg = refusal.to_string();
            assert!(
                msg.starts_with("Server.listen: mount `")
                    && msg.contains("is not a well-formed mount prefix"),
                "{msg}"
            );
        }
        for prefix in ["", "/", "/assets", "/a-b/c.d~e_f"] {
            assert!(
                parse_routes(vec![server_static(prefix.to_owned(), "dir".to_owned())]).is_ok(),
                "{prefix:?}"
            );
        }
    }

    /// Prove the refusal: two mounts on one prefix, whatever spelling of the
    /// root they use, are refused; a prefix nested under another is not.
    #[test]
    #[allow(clippy::expect_used)] // test: every fixed prefix parses
    fn two_mounts_on_one_prefix_are_refused_at_listen() {
        let mounts = |prefixes: &[&str]| {
            parse_routes(
                prefixes
                    .iter()
                    .map(|p| server_static((*p).to_owned(), "dir".to_owned()))
                    .collect(),
            )
            .expect("the prefixes parse")
        };
        for pair in [["/a", "/a"], ["/", ""], ["", ""]] {
            let msg = mount_conflict(&mounts(&pair))
                .map(|r| r.to_string())
                .unwrap_or_default();
            assert!(msg.contains("serve one prefix"), "{pair:?}: {msg}");
        }
        assert_eq!(
            mount_conflict(&mounts(&["/", "/billing", "/billing/admin"])),
            None
        );
        let shared = mount_conflict(&mounts(&["/a", "/a"])).map(ServerStartRefusal::into_ipe_error);
        assert_eq!(
            shared.map(crate::ipe_error_kind),
            Some(crate::IpeErrorKind::Conflict)
        );
    }

    /// `/:p0/:p1/…` with `n` parameters.
    fn params_path(n: usize) -> String {
        (0..n).map(|i| format!("/:p{i}")).collect()
    }

    /// The parameter ceiling is the router's: a pattern at
    /// [`crate::encoding::MAX_SERVER_PARAMS`] parses and registers, and the
    /// router itself refuses (by panicking) one parameter more, which the
    /// parse refuses first as a typed ceiling.
    #[test]
    #[allow(clippy::expect_used)] // test: the at-cap pattern parses
    fn max_server_params_matches_the_router() {
        let cap = crate::encoding::MAX_SERVER_PARAMS;
        let at_cap = params_path(cap);
        let pattern = crate::encoding::ServerPattern::parse(&at_cap).expect("at the cap parses");
        let path = pattern.router_path().to_owned();
        let mr = method_router(EndpointMethod::Get, pattern, name_echo());
        assert!(
            insert_endpoint(
                axum::Router::new(),
                &path,
                mr,
                quoted_endpoint("GET", &at_cap)
            )
            .is_ok()
        );
        let past_cap = params_path(cap.saturating_add(1));
        assert_eq!(
            crate::encoding::ServerPattern::parse(&past_cap).err(),
            Some(crate::encoding::ServerPatternRefusal::TooManyParams { cap })
        );
        let router_refuses = std::panic::catch_unwind(|| {
            axum::Router::<()>::new().route(&past_cap, axum::routing::get(|| async {}))
        })
        .is_err();
        assert!(router_refuses, "the router admits `{past_cap}`");
    }

    /// Prove the backstop's refusal: an insert the router rejects is answered
    /// as its own typed `Conflict` naming the endpoint, never relabelled as a
    /// handler conflict whose cause it may not be.
    #[test]
    #[allow(clippy::expect_used)] // test: the fixed pattern parses
    fn a_router_rejected_insert_is_its_own_refusal() {
        let pattern = || crate::encoding::ServerPattern::parse("/a").expect("parses");
        let mr = || method_router(EndpointMethod::Get, pattern(), name_echo());
        let app = insert_endpoint(
            axum::Router::new(),
            "/a",
            mr(),
            quoted_endpoint("GET", "/a"),
        )
        .expect("the first insert registers");
        let refused = insert_endpoint(app, "/a", mr(), quoted_endpoint("GET", "/a")).err();
        assert_eq!(
            refused,
            Some(ServerStartRefusal::RouterRejected {
                endpoint: quoted_endpoint("GET", "/a")
            })
        );
        let Some(refused) = refused else {
            return;
        };
        let error = refused.into_ipe_error();
        assert_eq!(
            crate::ipe_error_kind(error.clone()),
            crate::IpeErrorKind::Conflict
        );
        let msg = crate::ipe_error_message(error);
        assert!(
            msg.contains("`GET /a`") && !msg.contains("conflicts"),
            "{msg}"
        );
    }

    /// Prove the refusal of log hazards: a refused endpoint's quoted text has
    /// every control, bidi and escape character as a visible escape, so a
    /// path cannot forge a log record or drive a terminal.
    #[test]
    fn a_refused_endpoint_is_quoted_scrubbed() {
        for (raw, escaped) in [
            ("/a\nGET /b", "\\n"),
            ("/a\u{1b}[2J", "\\u{1b}"),
            ("/a\u{202e}b", "\\u{202e}"),
            ("/a\\n", "\\\\n"),
        ] {
            // A trailing catch-all makes every path a refused one.
            let refused = parse_routes(vec![get_route(&format!("{raw}/*rest"))]).err();
            let msg = refused.map(|r| r.to_string()).unwrap_or_default();
            assert!(
                msg.contains(escaped) && !msg.contains('\n') && !msg.contains('\u{1b}'),
                "{raw:?}: {msg:?}"
            );
            assert!(!msg.contains('\u{202e}'), "{raw:?}: {msg:?}");
        }
        assert_eq!(RefusedText::new("a\tb").as_str(), "a\\tb");
    }

    /// Prove the bound on a refused method: a method of any length is quoted
    /// as a short excerpt, so a refusal's size never follows its input.
    #[test]
    fn a_refused_method_is_quoted_as_an_excerpt() {
        let method = "X".repeat(10_000);
        let refused = parse_routes(vec![handler_route(&method, "/ok")]).err();
        assert_eq!(
            refused.as_ref().map(|r| r.cause.clone()),
            Some(RouteCause::Method)
        );
        let msg = refused.map(|r| r.to_string()).unwrap_or_default();
        let quoted = format!("`{} /ok`", excerpt(&method, METHOD_EXCERPT_CHARS));
        assert!(msg.contains(&quoted), "{msg:.200}");
        assert!(msg.len() < 400, "{msg:.200}");
        assert_eq!(excerpt("CONNECT", METHOD_EXCERPT_CHARS), "CONNECT");
    }

    /// Every listen refusal fails with the kind it is, never `Unexpected`.
    #[test]
    fn every_start_refusal_has_its_own_kind() {
        use crate::IpeErrorKind as K;
        use crate::encoding::{MountBaseRefusal, ServerPatternRefusal};
        let text = || RefusedText::new("GET /a");
        let route = |cause| {
            ServerStartRefusal::Route(EndpointRefusal {
                endpoint: text(),
                cause,
            })
        };
        let too_many = ServerPatternRefusal::TooManyParams {
            cap: crate::encoding::MAX_SERVER_PARAMS,
        };
        let cases = [
            (route(RouteCause::Method), K::InvalidInput),
            (
                route(RouteCause::Pattern(ServerPatternRefusal::NotAbsolute)),
                K::InvalidInput,
            ),
            (route(RouteCause::Pattern(too_many)), K::LimitExceeded),
            (
                route(RouteCause::Prefix(MountBaseRefusal::TooLong { len: 1 })),
                K::LimitExceeded,
            ),
            (
                route(RouteCause::Prefix(MountBaseRefusal::NoLeadingSlash)),
                K::InvalidInput,
            ),
            (
                ServerStartRefusal::Overlap {
                    earlier: text(),
                    later: text(),
                },
                K::Conflict,
            ),
            (
                ServerStartRefusal::SharedPrefix {
                    earlier: text(),
                    later: text(),
                },
                K::Conflict,
            ),
            (
                ServerStartRefusal::RouterRejected { endpoint: text() },
                K::Conflict,
            ),
        ];
        for (refusal, kind) in cases {
            let shown = refusal.to_string();
            assert_eq!(
                crate::ipe_error_kind(refusal.into_ipe_error()),
                kind,
                "{shown}"
            );
        }
    }

    /// An endpoint registers under its rendered spelling behind the
    /// listener's canonical rewrite, so every spelling of its path reaches it
    /// and a parameter still captures one segment.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed patterns parse and fixed requests build
    async fn an_endpoint_routes_every_spelling_of_its_path() {
        use tower::ServiceExt;
        let mut app = axum::Router::new();
        for raw in ["/greet/:name", "/café", "/%61pi/"] {
            let pattern = crate::encoding::ServerPattern::parse(raw).expect("well-formed");
            let path = pattern.router_path().to_owned();
            app = app.route(
                &path,
                method_router(EndpointMethod::Get, pattern, name_echo()),
            );
        }
        let app = behind_listener(app);
        for (uri, status) in [
            ("/greet/bob", axum::http::StatusCode::OK),
            ("/%67reet/bob", axum::http::StatusCode::OK),
            ("/caf%C3%A9", axum::http::StatusCode::OK),
            ("/%63af%c3%a9", axum::http::StatusCode::OK),
            ("/api/", axum::http::StatusCode::OK),
            ("/%61pi/", axum::http::StatusCode::OK),
            ("/api", axum::http::StatusCode::NOT_FOUND),
            ("/greet/a/b", axum::http::StatusCode::NOT_FOUND),
        ] {
            let wire = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("test request builds");
            let resp = match app.clone().oneshot(wire).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            assert_eq!(resp.status(), status, "{uri}");
        }
    }

    /// Prove the refusals: a literal spelled like a router capture
    /// (`{id}`, `{{id}}`, `{*rest}`) is a literal, never a capture, so it
    /// serves only its own text and refuses every other segment.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed patterns parse and fixed requests build
    async fn a_brace_literal_never_routes_as_a_capture() {
        use tower::ServiceExt;
        let mut app = axum::Router::new();
        for raw in ["/u/{id}", "/v/{{id}}", "/w/%7B%2Arest%7D"] {
            let pattern = crate::encoding::ServerPattern::parse(raw).expect("well-formed");
            let path = pattern.router_path().to_owned();
            app = insert_endpoint(
                app,
                &path,
                method_router(EndpointMethod::Get, pattern, name_echo()),
                RefusedText::new(raw),
            )
            .expect("a brace literal registers as a literal");
        }
        let app = behind_listener(app);
        for (uri, status) in [
            ("/u/%7Bid%7D", axum::http::StatusCode::OK),
            ("/u/{id}", axum::http::StatusCode::OK),
            ("/u/bob", axum::http::StatusCode::NOT_FOUND),
            ("/u/id", axum::http::StatusCode::NOT_FOUND),
            ("/v/%7B%7Bid%7D%7D", axum::http::StatusCode::OK),
            ("/v/{id}", axum::http::StatusCode::NOT_FOUND),
            ("/v/bob", axum::http::StatusCode::NOT_FOUND),
            ("/w/%7B*rest%7D", axum::http::StatusCode::OK),
            ("/w/a", axum::http::StatusCode::NOT_FOUND),
            ("/w/a/b", axum::http::StatusCode::NOT_FOUND),
        ] {
            let wire = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("test request builds");
            let resp = match app.clone().oneshot(wire).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            assert_eq!(resp.status(), status, "{uri}");
        }
    }

    /// The listener refuses an `IPE_WEB_FRAME_ANCESTORS` with no
    /// `frame-ancestors` representation before it binds. The value is read
    /// once per process, so the check runs in a child holding it.
    #[test]
    fn listen_refuses_an_unrepresentable_frame_ancestors() {
        let (refused, out) = crate::telemetry::frame_ancestors_child::refused(
            module_path!(),
            "listen_frame_ancestors_child",
            "a;b",
        );
        assert!(refused, "the child must observe the refusal:\n{out}");
    }

    /// The child half of `listen_refuses_an_unrepresentable_frame_ancestors`;
    /// a no-op unless it runs with `IPE_WEB_FRAME_ANCESTORS=a;b`.
    #[tokio::test]
    #[ignore = "run as a child process by listen_refuses_an_unrepresentable_frame_ancestors"]
    async fn listen_frame_ancestors_child() {
        if crate::system::read_env_var(crate::telemetry::FRAME_ANCESTORS_ENV).as_deref()
            != Ok("a;b")
        {
            return;
        }
        // A listener that got past the refusal would bind and serve forever;
        // the timeout turns that regression into a failure instead of a hang.
        let listened: IpeResult<crate::IpeError, ()> = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_listen(0, Vec::new()),
        )
        .await
        .expect("a refused framing policy must return before binding, not serve");
        let IpeResult::Err(error) = listened else {
            panic!("a `;` in IPE_WEB_FRAME_ANCESTORS must refuse the listener");
        };
        assert_eq!(
            crate::ipe_error_kind(error.clone()),
            crate::IpeErrorKind::InvalidInput,
            "{error:?}"
        );
        let msg = crate::ipe_error_message(error);
        assert!(
            msg.starts_with("Server.listen: IPE_WEB_FRAME_ANCESTORS holds `;`"),
            "{msg}"
        );
        println!("\n{}", crate::telemetry::frame_ancestors_child::REFUSED);
    }

    /// A loopback app listener prints no exposure warning.
    #[test]
    fn a_loopback_listener_prints_no_exposure_warning() {
        use crate::app_config::{ListenHost, LoopbackIp};
        assert_eq!(
            exposure_warning(ListenHost::Loopback(LoopbackIp::DEFAULT)),
            None
        );
    }

    /// The lines `bind_app_listener` prints: the readiness line alone for a
    /// loopback host, then the exposure warning for an exposed one.
    #[test]
    fn an_exposed_listener_prints_the_warning_after_its_readiness_line() {
        use crate::app_config::{ExposedBy, ListenHost, LoopbackIp};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let none = crate::inbound_authority::DeclaredNames::none();
        let admission = "host admission: IP literals and localhost; set \
                         IPE_HTTP_ALLOWED_HOSTS=<name> to serve a DNS name"
            .to_owned();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000);
        assert_eq!(
            startup_lines(loopback, ListenHost::Loopback(LoopbackIp::DEFAULT), &none),
            vec![
                "listening on http://127.0.0.1:8000".to_owned(),
                admission.clone()
            ]
        );
        let exposed = ListenHost::Exposed {
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            by: ExposedBy::EnvVar,
        };
        let mut expected = vec!["listening on http://0.0.0.0:8000".to_owned(), admission];
        expected.extend(exposure_warning(exposed).into_iter().flatten());
        assert_eq!(expected.len(), 4, "an exposed host warns in two lines");
        assert_eq!(
            startup_lines(SocketAddr::new(exposed.ip(), 8000), exposed, &none),
            expected
        );
        let declared =
            crate::inbound_authority::DeclaredNames::parse("a.example, .b.example").unwrap();
        assert_eq!(
            admission_line(&declared),
            "host admission: IP literals and localhost, and 2 declared name(s)"
        );
    }

    /// An exposure the operator opted in to warns with the parsed address and
    /// the way back to loopback.
    #[test]
    fn an_env_exposure_warns_with_the_parsed_address() {
        use crate::app_config::{ExposedBy, ListenHost};
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let warn = |ip: IpAddr| {
            exposure_warning(ListenHost::Exposed {
                ip,
                by: ExposedBy::EnvVar,
            })
        };
        assert_eq!(
            warn(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some([
                "warning: listening on every interface (0.0.0.0) because IPE_HTTP_BIND=0.0.0.0; \
                 other hosts on the network can reach this app"
                    .to_owned(),
                "  to keep it local, unset IPE_HTTP_BIND (the default is 127.0.0.1)".to_owned(),
            ])
        );
        // `0:0::0` parses to the unspecified IPv6 address, printed `::`.
        let parsed: Result<IpAddr, _> = "0:0::0".parse();
        assert_eq!(parsed, Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        let Ok(parsed) = parsed else { return };
        let first = warn(parsed).map(|[first, _]| first).unwrap_or_default();
        assert!(
            first.contains("every interface (::) because IPE_HTTP_BIND=::;")
                && !first.contains("0:0::0"),
            "{first}"
        );
        let first = warn(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
            .map(|[first, _]| first)
            .unwrap_or_default();
        assert!(
            first.starts_with("warning: listening on 192.0.2.7 because IPE_HTTP_BIND=192.0.2.7;"),
            "{first}"
        );
    }

    /// An exposure the app's own setting opted in to names the setting.
    #[test]
    fn a_setting_exposure_warns_naming_the_setting() {
        use crate::app_config::{ExposedBy, ListenHost};
        use std::net::{IpAddr, Ipv4Addr};
        assert_eq!(
            exposure_warning(ListenHost::Exposed {
                ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                by: ExposedBy::Setting,
            }),
            Some([
                "warning: listening on every interface (0.0.0.0) because the app sets \
                 Host.bind Host.allInterfaces; other hosts on the network can reach this app"
                    .to_owned(),
                "  to keep it local, set Host.bind Host.loopback, or IPE_HTTP_BIND=127.0.0.1"
                    .to_owned(),
            ])
        );
    }

    /// A present `IPE_HTTP_BIND` that is not an IP address refuses the listener
    /// before it binds.
    #[tokio::test]
    async fn listen_refuses_a_bind_that_is_not_an_ip_address() {
        for raw in ["localhost", "127.0.0.1:8080", "[::1]", " 127.0.0.1"] {
            crate::system::locked_set_var("IPE_HTTP_BIND", raw);
            // A listener that got past the refusal would bind and serve forever;
            // the timeout turns that regression into a failure instead of a hang.
            let listened: Result<IpeResult<crate::IpeError, ()>, _> = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                server_listen(0, Vec::new()),
            )
            .await;
            crate::system::locked_remove_var("IPE_HTTP_BIND");
            let Ok(IpeResult::Err(error)) = listened else {
                panic!("IPE_HTTP_BIND={raw:?} must refuse the listener: {listened:?}");
            };
            // An operator's malformed setting is invalid input, never the
            // `Unexpected` catch-all a bare string lands in.
            assert_eq!(
                crate::ipe_error_kind(error.clone()),
                crate::IpeErrorKind::InvalidInput,
                "{error:?}"
            );
            assert!(
                crate::ipe_error_message(error)
                    .starts_with("Server.listen: IPE_HTTP_BIND must be an IP address"),
                "IPE_HTTP_BIND={raw:?}"
            );
        }
    }

    /// A program port no TCP listener can take refuses `Server.listen` as a
    /// typed `InvalidInput` before it binds, never the `Unexpected` catch-all.
    #[tokio::test]
    async fn listen_on_an_out_of_range_port_is_invalid_input() {
        crate::system::locked_remove_var(crate::env_registry::listen::SERVER_PORT.name());
        crate::system::locked_remove_var(crate::LISTEN_PORT_RELOCATION_ENV);
        for port in [0, -1, 65_536, i64::MAX] {
            let listened: Result<IpeResult<crate::IpeError, ()>, _> = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                server_listen(port, Vec::new()),
            )
            .await;
            let Ok(IpeResult::Err(error)) = listened else {
                panic!("port {port} must refuse the listener: {listened:?}");
            };
            assert_eq!(
                crate::ipe_error_kind(error.clone()),
                crate::IpeErrorKind::InvalidInput,
                "{error:?}"
            );
            assert_eq!(
                crate::ipe_error_message(error),
                format!("Server.listen: port {port} is not a TCP port in 1..=65535")
            );
        }
    }

    /// A set `IPE_SERVER_PORT` that is not a port refuses `Server.listen` as
    /// typed invalid input naming the variable, before any bind, never falling
    /// back to the program's port.
    #[tokio::test]
    async fn listen_under_a_malformed_operator_port_is_invalid_input() {
        let var = crate::env_registry::listen::SERVER_PORT.name();
        crate::system::locked_remove_var(crate::LISTEN_PORT_RELOCATION_ENV);
        for raw in ["99999", "0", "abc", "", " 8080"] {
            crate::system::locked_set_var(var, raw);
            let listened: Result<IpeResult<crate::IpeError, ()>, _> = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                server_listen(8000, Vec::new()),
            )
            .await;
            crate::system::locked_remove_var(var);
            assert!(
                matches!(&listened, Ok(IpeResult::Err(_))),
                "{var}={raw:?} must refuse the listener: {listened:?}"
            );
            let Ok(IpeResult::Err(error)) = listened else {
                return;
            };
            assert_eq!(
                crate::ipe_error_kind(error.clone()),
                crate::IpeErrorKind::InvalidInput,
                "{error:?}"
            );
            let message = crate::ipe_error_message(error);
            assert!(
                message
                    .starts_with("Server.listen: IPE_SERVER_PORT must be a TCP port in 1..=65535"),
                "{var}={raw:?}: {message}"
            );
        }
    }

    #[test]
    fn server_header_is_case_insensitive_go_parity() {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let req = ServerRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            body: String::new(),
            headers,
            params: HashMap::new(),
            query: HashMap::new(),
            cookies: HashMap::new(),
            remoteAddr: String::new(),
        };
        for probe in ["content-type", "Content-Type", "CONTENT-TYPE"] {
            assert!(
                matches!(
                    server_header(probe.to_string(), req.clone()),
                    IpeMaybe::Just(ref v) if v == "application/json"
                ),
                "lookup {probe:?} should resolve to the stored value",
            );
        }
        assert!(matches!(
            server_header("x-missing".to_string(), req.clone()),
            IpeMaybe::Nothing
        ));
    }

    /// A request carrying a planted credential in every client-supplied field.
    fn secret_laden_request() -> ServerRequest {
        let pair = |k: &str, v: &str| HashMap::from([(k.to_owned(), v.to_owned())]);
        ServerRequest {
            method: "POST".to_owned(),
            path: "/reset/P4THT0K".to_owned(),
            body: "password=PW0RD".to_owned(),
            headers: pair("Authorization", "Bearer S3CR3T"),
            params: pair("id", "P4R4M"),
            query: pair("token", "QT0K3N"),
            cookies: pair("sid", "T0K3N"),
            remoteAddr: "203.0.113.9".to_owned(),
        }
    }

    const PLANTED: [&str; 7] = [
        "S3CR3T",
        "T0K3N",
        "PW0RD",
        "P4R4M",
        "QT0K3N",
        "203.0.113.9",
        "P4THT0K",
    ];

    #[test]
    fn request_debug_prints_no_client_supplied_value() {
        let req = secret_laden_request();
        for shown in [format!("{req:?}"), format!("{req:#?}")] {
            for secret in PLANTED {
                assert!(!shown.contains(secret), "{secret} leaked: {shown}");
            }
            assert!(shown.contains("\"POST\""), "{shown}");
            assert!(shown.contains(crate::redact::REDACTED));
        }
        assert!(matches!(
            server_get_cookie("sid".to_owned(), req),
            IpeMaybe::Just(ref v) if v == "T0K3N"
        ));
    }

    #[test]
    fn cookie_and_response_debug_print_no_secret() {
        let cookie = cookie("sid", "T0K3N");
        let shown = format!("{cookie:?}");
        assert!(!shown.contains("T0K3N"), "{shown}");
        assert!(shown.contains("\"sid\""));
        let line = SetCookie::new(
            &parsed_name("sid"),
            &CookieValue::encode("T0K3N"),
            CookieAttributes {
                path: CookiePath::root(),
                http_only: true,
                same_site: SameSite::Lax,
                secure: true,
                max_age_secs: None,
            },
        );
        let shown = format!("{line:?}");
        assert_eq!(shown, "SetCookie(<redacted>)");

        let mut resp = server_text("session=T0K3N".to_owned());
        resp.headers
            .insert("Authorization".to_owned(), "Bearer S3CR3T".to_owned());
        resp.cookies.push(SetCookie::new(
            &parsed_name("sid"),
            &CookieValue::encode("T0K3N"),
            CookieAttributes {
                path: CookiePath::root(),
                http_only: true,
                same_site: SameSite::Lax,
                secure: false,
                max_age_secs: None,
            },
        ));
        let shown = format!("{resp:?}");
        for secret in ["T0K3N", "S3CR3T"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("status: 200"));
    }

    /// A router serving `h` for GET at the parsed `raw` endpoint path.
    #[allow(clippy::expect_used)] // test: a fixed endpoint path parses
    fn endpoint_router(raw: &str, h: ErasedHandler) -> axum::Router {
        let pattern = crate::encoding::ServerPattern::parse(raw).expect("well-formed");
        let path = pattern.router_path().to_owned();
        axum::Router::new().route(&path, method_router(EndpointMethod::Get, pattern, h))
    }

    /// Run `build_request` inside a router matched on `pattern`.
    ///
    /// Returns what `build_request` produced for `wire`, or `None` when the
    /// router never reached the handler (no route matched).
    #[allow(clippy::expect_used)] // test: a fixed endpoint path parses
    async fn routed_build(
        pattern: &str,
        wire: axum::http::Request<axum::body::Body>,
    ) -> Option<Result<ServerRequest, RequestRejection>> {
        use tower::ServiceExt;
        let parsed = crate::encoding::ServerPattern::parse(pattern).expect("well-formed");
        let path = parsed.router_path().to_owned();
        let parsed = Arc::new(parsed);
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = std::sync::Arc::clone(&slot);
        let app = axum::Router::new().route(
            &path,
            axum::routing::any(move |req: axum::extract::Request| {
                let seen = std::sync::Arc::clone(&seen);
                let parsed = Arc::clone(&parsed);
                async move {
                    let built = build_request(req, &parsed).await.map(|(r, _)| r);
                    if let Ok(mut s) = seen.lock() {
                        *s = Some(built);
                    }
                    ""
                }
            }),
        );
        let _ = behind_listener(app).oneshot(wire).await;
        slot.lock().ok().and_then(|mut s| s.take())
    }

    /// Prove the refusal: a handler reached for a path its pattern does not
    /// match (the router and the pattern disagree) answers the fixed 500,
    /// never runs with an empty parameter table.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed patterns parse and fixed requests build
    async fn build_request_on_a_path_its_pattern_does_not_match_is_refused() {
        for (pattern, uri) in [
            ("/greet/:name", "/"),
            ("/greet/:name", "/greet/a/b"),
            ("/greet/:name", "/hello/bob"),
            ("/greet/:name", "/greet/bob/"),
            ("/a/", "/a"),
        ] {
            let pattern = crate::encoding::ServerPattern::parse(pattern).expect("well-formed");
            let mut wire = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("test request builds");
            assert!(canonicalise(&mut wire).is_ok(), "{uri} parses");
            assert!(
                matches!(
                    build_request(wire, &pattern).await,
                    Err(RequestRejection::Unrouted)
                ),
                "{uri}"
            );
        }
        assert_eq!(
            RequestRejection::Unrouted.status_and_reason(),
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error"
            )
        );
    }

    /// Prove the refusal: a parameter segment with a malformed escape is
    /// refused by the listener with 400 and never reaches the handler.
    #[tokio::test]
    async fn a_malformed_parameter_escape_never_reaches_the_handler() {
        for uri in ["/u/%zz", "/u/%", "/u/%C3"] {
            let (status, body, runs) = serve_counted_with(uri, behind_listener).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{uri:?}");
            assert_eq!(body, "Bad Request", "{uri:?} must not echo");
            assert_eq!(runs, 0, "{uri:?} must never reach the handler");
        }
    }

    /// A parameter is the strictly decoded segment: a UTF-8 escape decodes to
    /// its character and an escaped `/` stays inside the one segment.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed requests build
    async fn a_parameter_is_its_decoded_segment() {
        for (uri, want) in [
            ("/greet/caf%C3%A9", "café"),
            ("/greet/a%2Fb", "a/b"),
            ("/greet/a%3Ab", "a:b"),
            ("/greet/bob", "bob"),
        ] {
            let wire = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("test request builds");
            let built = routed_build("/greet/:name", wire).await;
            let Some(Ok(req)) = built else {
                assert!(matches!(built, Some(Ok(_))), "{uri} must build");
                return;
            };
            assert_eq!(
                req.params.get("name").map(String::as_str),
                Some(want),
                "{uri}"
            );
            assert_eq!(req.params.len(), 1, "{uri}");
        }
    }

    /// A request that reaches a Server handler without the listener's URL
    /// parse is refused with the fixed 500, never parsed afresh: a well-formed
    /// URL and a malformed one are refused alike.
    #[tokio::test]
    async fn build_request_without_the_listener_parse_is_refused() {
        for uri in ["/u/x?q=1", "/u/%zz"] {
            let (status, body, runs) = serve_counted_with(uri, |app| app).await;
            assert_eq!(
                status,
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{uri:?}"
            );
            assert_eq!(body, "Internal Server Error", "{uri:?} must not echo");
            assert_eq!(runs, 0, "{uri:?} must never reach the handler");
        }
        assert_eq!(
            RequestRejection::Unparsed.status_and_reason(),
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error"
            )
        );
    }

    /// A `Cookie` header with one non-ASCII byte keeps every other cookie: the
    /// pair holding the byte is skipped, the session cookie beside it is read.
    #[tokio::test]
    async fn build_request_keeps_the_cookies_beside_a_non_ascii_pair() {
        let tossed = axum::http::HeaderValue::from_bytes(b"x=\x80; sid=v")
            .expect("obs-text is a valid header value");
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .header(axum::http::header::COOKIE, tossed)
            .header(axum::http::header::COOKIE, "csrf=t")
            .body(axum::body::Body::empty())
            .expect("test request builds");
        let Some(Ok(req)) = routed_build("/", wire).await else {
            panic!("the request builds");
        };
        assert_eq!(req.cookies.get("sid").map(String::as_str), Some("v"));
        assert_eq!(req.cookies.get("csrf").map(String::as_str), Some("t"));
        assert!(!req.cookies.contains_key("x"), "{:?}", req.cookies);
        assert!(
            !req.headers.contains_key("Cookie"),
            "the cookie parser alone reads `Cookie`"
        );
    }

    /// Serve one GET `/u/1` carrying `headers` through the listener to a
    /// counting handler; returns the status, the body and the run count.
    #[allow(clippy::expect_used)] // test: fixed requests build
    async fn serve_with_headers(
        headers: &[(&str, &[u8])],
    ) -> (axum::http::StatusCode, String, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let handler: ErasedHandler = Arc::new(move |req: ServerRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            let resp = server_text(
                req.headers
                    .get("Authorization")
                    .cloned()
                    .unwrap_or_default(),
            );
            Box::pin(async move { Ok(resp) })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<ServerResponse, String>> + Send>,
                >
        });
        let app = behind_listener(endpoint_router("/u/:id", handler));
        let mut wire = axum::http::Request::builder().method("GET").uri("/u/1");
        for (name, value) in headers {
            wire = wire.header(
                *name,
                axum::http::HeaderValue::from_bytes(value).expect("a valid header value"),
            );
        }
        let resp = match app
            .oneshot(
                wire.body(axum::body::Body::empty())
                    .expect("test request builds"),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => match e {},
        };
        let status = resp.status();
        let body = axum_body_string(resp).await;
        (status, body, runs.load(Ordering::SeqCst))
    }

    /// Prove the refusal: two `Authorization` headers, or a decodable one
    /// beside an undecodable copy, answer the fixed 400 and never reach the
    /// handler; the listener and the handler can never read different copies.
    #[tokio::test]
    async fn a_repeated_singleton_header_never_reaches_the_server_handler() {
        for headers in [
            [
                ("authorization", b"Bearer a".as_slice()),
                ("authorization", b"Bearer b".as_slice()),
            ],
            [
                ("authorization", b"Bearer \xC3\xA9".as_slice()),
                ("authorization", b"Bearer b".as_slice()),
            ],
            [
                ("host", b"a.example".as_slice()),
                ("host", b"b.example".as_slice()),
            ],
        ] {
            let (status, body, runs) = serve_with_headers(&headers).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{headers:?}");
            assert_eq!(body, "Bad Request", "{headers:?} must not echo");
            assert_eq!(runs, 0, "{headers:?} must never reach the handler");
        }
        let (status, body, runs) =
            serve_with_headers(&[("authorization", b"Bearer a".as_slice())]).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "Bearer a");
        assert_eq!(runs, 1);
    }

    /// A list header's copies reach the handler combined in arrival order.
    #[tokio::test]
    async fn build_request_combines_a_list_header_in_order() {
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .header(axum::http::header::ACCEPT, "text/html")
            .header(axum::http::header::ACCEPT, "application/json")
            .body(axum::body::Body::empty())
            .expect("test request builds");
        let built = routed_build("/", wire).await;
        let Some(Ok(req)) = built else {
            assert!(matches!(built, Some(Ok(_))), "a list header must build");
            return;
        };
        assert_eq!(
            req.headers.get("Accept").map(String::as_str),
            Some("text/html, application/json")
        );
    }

    /// The fold of `headers`, for the remote-address tests.
    #[allow(clippy::expect_used)] // test: fixed names and values are valid
    fn folded(headers: &[(&'static str, &'static str)]) -> crate::http_header::RequestHeaders {
        let mut map = axum::http::HeaderMap::new();
        for (name, value) in headers {
            map.append(*name, axum::http::HeaderValue::from_static(value));
        }
        crate::http_header::RequestHeaders::parse(&map).expect("the headers fold")
    }

    /// Behind a trusted proxy the address is the rightmost `X-Forwarded-For`
    /// entry, the one that proxy appended; a client-written entry left of it
    /// never wins, and a value that is not an IP address falls back to the peer.
    #[test]
    fn remote_addr_takes_rightmost_xff_entry() {
        let peer = Some(std::net::IpAddr::from([10, 0, 0, 1]));
        let forwarded = folded(&[("x-forwarded-for", "6.6.6.6, 1.2.3.4")]);
        assert_eq!(remote_address(&forwarded, peer, true), "1.2.3.4");
        let split = folded(&[
            ("x-forwarded-for", "6.6.6.6"),
            ("x-forwarded-for", "1.2.3.4"),
        ]);
        assert_eq!(remote_address(&split, peer, true), "1.2.3.4");
        for text in ["not-an-ip", "1.2.3.4, ", "1.2.3.4, evil"] {
            let junk = folded(&[("x-forwarded-for", text)]);
            assert_eq!(remote_address(&junk, peer, true), "10.0.0.1", "{text:?}");
        }
        let real = folded(&[("x-real-ip", "1.2.3.4")]);
        assert_eq!(remote_address(&real, peer, true), "1.2.3.4");
        let real_junk = folded(&[("x-real-ip", "spoofed text")]);
        assert_eq!(remote_address(&real_junk, peer, true), "10.0.0.1");
        assert_eq!(remote_address(&forwarded, peer, false), "10.0.0.1");
        assert_eq!(remote_address(&forwarded, None, false), "");
    }

    /// Serve `uri` through a real `method_router` routed on `/u/:id`.
    ///
    /// The handler answers `"{id}|{q}"` from its path parameter and query, and
    /// counts its runs. Returns the status, the body and the run count.
    async fn serve_counted(uri: &str) -> (axum::http::StatusCode, String, usize) {
        serve_counted_with(uri, behind_listener).await
    }

    /// [`serve_counted`] with the router passed through `listener` first.
    async fn serve_counted_with(
        uri: &str,
        listener: fn(axum::Router) -> axum::Router,
    ) -> (axum::http::StatusCode, String, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;
        let runs = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&runs);
        let handler: ErasedHandler = Arc::new(move |req: ServerRequest| {
            counter.fetch_add(1, Ordering::SeqCst);
            let id = req.params.get("id").cloned().unwrap_or_default();
            let q = req.query.get("q").cloned().unwrap_or_default();
            let resp = server_text(format!("{id}|{q}"));
            Box::pin(async move { Ok(resp) })
                as std::pin::Pin<
                    Box<dyn std::future::Future<Output = Result<ServerResponse, String>> + Send>,
                >
        });
        let app = listener(endpoint_router("/u/:id", handler));
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(axum::body::Body::empty());
        assert!(wire.is_ok(), "{uri:?} must be a buildable request URI");
        let Ok(wire) = wire else {
            return (
                axum::http::StatusCode::IM_A_TEAPOT,
                String::new(),
                usize::MAX,
            );
        };
        let resp = match app.oneshot(wire).await {
            Ok(r) => r,
            Err(e) => match e {},
        };
        let status = resp.status();
        let body = axum_body_string(resp).await;
        (status, body, runs.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn malformed_url_components_are_refused_before_the_handler() {
        // Prove the refusals: each malformed path parameter or query answers
        // 400 with the fixed reason, and the handler never runs.
        let mut past_cap: Vec<String> = (0..crate::encoding::MAX_QUERY_PAIRS.get())
            .map(|i| format!("k{i}=v"))
            .collect();
        past_cap.push("extra=1".to_string());
        let too_many_pairs = format!("/u/x?{}", past_cap.join("&"));
        for uri in [
            "/u/%zz",
            "/u/trailing%",
            "/u/%C3",
            "/u/%C0%AF",
            "/u/x?q=%zz",
            "/u/x?%C3=1",
            too_many_pairs.as_str(),
        ] {
            let (status, body, runs) = serve_counted(uri).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{uri:?}");
            assert_eq!(body, "Bad Request", "{uri:?} must not echo the request");
            assert_eq!(runs, 0, "{uri:?} must never reach the handler");
        }
    }

    #[tokio::test]
    async fn well_formed_url_components_decode_once_by_grammar() {
        // Happy path: `+` is literal in a path and a space in a query, every
        // escape is decoded exactly once, and the handler runs once.
        let mut at_cap: Vec<String> = (1..crate::encoding::MAX_QUERY_PAIRS.get())
            .map(|i| format!("k{i}=v"))
            .collect();
        at_cap.push("q=last".to_string());
        let pairs_at_cap = format!("/u/x?{}", at_cap.join("&"));
        for (uri, want) in [
            ("/u/a+b", "a+b|"),
            ("/u/x?q=a+b", "x|a b"),
            ("/u/%2541", "%41|"),
            ("/u/caf%C3%A9", "café|"),
            ("/u/x?q=1&q=2", "x|1"),
            (pairs_at_cap.as_str(), "x|last"),
            // An encoded slash stays inside its one segment: the router matches
            // the raw path (one segment, so `/u/:id` and never `/u/:a/:b`), and
            // the parameter is its single strict decode. Nothing joins a path
            // parameter into a file path, so no traversal opens.
            ("/u/a%2Fb", "a/b|"),
        ] {
            let (status, body, runs) = serve_counted(uri).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{uri:?}");
            assert_eq!(body, want, "{uri:?}");
            assert_eq!(runs, 1, "{uri:?}");
        }
    }

    /// A fresh scratch directory for one static-serving test.
    fn static_fixture_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("ipe-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp static dir");
        dir
    }

    /// Serve `uri` through `strict_serve_dir_with(dir, regime)` mounted at
    /// `/static`. Returns the status and body.
    async fn serve_static_dir(
        dir: &std::path::Path,
        regime: crate::path_core::Regime,
        uri: &str,
    ) -> (axum::http::StatusCode, String) {
        use tower::ServiceExt;
        let base = crate::encoding::MountBase::parse("/static").expect("the prefix parses");
        let files =
            axum::Router::new().fallback_service(strict_serve_dir_with(dir.to_path_buf(), regime));
        let app = behind_listener(MountTable::new(vec![(base, files)]).below(axum::Router::new()));
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("test request builds");
        let resp = match app.oneshot(wire).await {
            Ok(r) => r,
            Err(e) => match e {},
        };
        let status = resp.status();
        let body = axum_body_string(resp).await;
        (status, body)
    }

    /// Serve `uri` through `strict_serve_dir` mounted at `/static` over a
    /// fresh directory holding `hello.txt`. Returns the status and body.
    async fn serve_static(uri: &str) -> (axum::http::StatusCode, String) {
        let dir = static_fixture_dir("strict-static");
        std::fs::write(dir.join("hello.txt"), "hi").expect("static fixture file");
        let out = serve_static_dir(&dir, crate::path_core::HOST, uri).await;
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn static_request_windows_refuses_escaping_paths() {
        use crate::path_core::{ElementRefusal, Regime, RelPathRefusal};
        let root = std::path::Path::new("C:\\site");
        let element = |why| StaticRefusal::Segment(RelPathRefusal::Element(why));
        let segment = StaticRefusal::Segment;
        for (uri, want) in [
            ("/a%5C..%5Cx", segment(RelPathRefusal::Separator)),
            ("/C:x", element(ElementRefusal::Colon)),
            ("/x:stream", element(ElementRefusal::Colon)),
            ("/CON", element(ElementRefusal::DosDevice)),
            ("/nul.txt", element(ElementRefusal::DosDevice)),
            ("/a/COM1", element(ElementRefusal::DosDevice)),
            ("/a%5CCOM1", segment(RelPathRefusal::Separator)),
            ("/LPT9.log", element(ElementRefusal::DosDevice)),
            ("/..%20", element(ElementRefusal::DotSpaceRun)),
            ("/..", element(ElementRefusal::Parent)),
            ("/a.", element(ElementRefusal::StrippedTail)),
            ("/a%2Fb", segment(RelPathRefusal::Separator)),
            ("/a%00b", segment(RelPathRefusal::Nul)),
            // An empty inner segment names no entry: `/a//b.css` is refused,
            // not collapsed to `a/b.css` as `ServeDir` alone would.
            ("/a//b.css", segment(RelPathRefusal::NotAName)),
        ] {
            assert_eq!(
                static_request(uri, root, Regime::Windows),
                Err(want),
                "{uri:?}"
            );
        }
        assert_eq!(
            static_request("/", root, Regime::Windows),
            Ok(StaticRequest::Root)
        );
        let file = static_request("/a/b.css/", root, Regime::Windows);
        assert!(
            matches!(&file, Ok(StaticRequest::File(rel)) if rel.as_str() == "a\\b.css"),
            "{file:?}"
        );
    }

    #[test]
    fn static_request_unix_accepts_legal_names() {
        use crate::path_core::{ElementRefusal, Regime, RelPathRefusal};
        let root = std::path::Path::new("/srv/site");
        for (uri, want) in [
            ("/CON", "CON"),
            ("/nul.txt", "nul.txt"),
            ("/x:stream", "x:stream"),
            ("/a.", "a."),
            ("/a%5Cb", "a\\b"),
            ("/fav%69con.ico", "favicon.ico"),
        ] {
            let got = static_request(uri, root, Regime::Unix);
            assert!(
                matches!(&got, Ok(StaticRequest::File(rel)) if rel.as_str() == want),
                "{uri:?}: {got:?}"
            );
        }
        for (uri, want) in [
            (
                "/a%2F..%2Fx",
                StaticRefusal::Segment(RelPathRefusal::Separator),
            ),
            (
                "/a/../x",
                StaticRefusal::Segment(RelPathRefusal::Element(ElementRefusal::Parent)),
            ),
            (
                "/a//b.css",
                StaticRefusal::Segment(RelPathRefusal::NotAName),
            ),
            (
                "/a/./b.css",
                StaticRefusal::Segment(RelPathRefusal::NotAName),
            ),
            ("/a%00b", StaticRefusal::Segment(RelPathRefusal::Nul)),
        ] {
            assert_eq!(
                static_request(uri, root, Regime::Unix),
                Err(want),
                "{uri:?}"
            );
        }
        let malformed = static_request("/a%zz", root, Regime::Unix);
        assert!(
            matches!(
                malformed,
                Err(StaticRefusal::Malformed(
                    crate::encoding::DecodeRefusal::MalformedEscape { .. }
                ))
            ),
            "{malformed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn static_request_refuses_a_non_text_root() {
        use std::os::unix::ffi::OsStrExt;
        let root = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/srv/\xff"));
        assert_eq!(
            static_request("/a.css", root, crate::path_core::Regime::Unix),
            Err(StaticRefusal::RootNotText)
        );
    }

    #[tokio::test]
    async fn serve_dir_gate_refuses_a_present_device_name_under_windows() {
        use crate::path_core::Regime;
        // Each name is a legal Linux file, so only the gate can refuse it.
        let names = ["CON", "nul.txt", "x:stream", "a."];
        let dir = static_fixture_dir("static-gate");
        for name in names {
            std::fs::write(dir.join(name), format!("body of {name}")).expect("static fixture file");
        }
        for name in names {
            let uri = format!("/static/{name}");
            let (status, body) = serve_static_dir(&dir, Regime::Windows, &uri).await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{uri:?}");
            assert!(!body.contains(name), "{uri:?} must not echo the path");
            let (status, body) = serve_static_dir(&dir, Regime::Unix, &uri).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{uri:?}");
            assert_eq!(body, format!("body of {name}"), "{uri:?}");
        }
        // `/a//b` names no entry, so it is refused on both regimes even though
        // `ServeDir` alone would serve `a/b`.
        std::fs::create_dir_all(dir.join("a")).expect("static fixture dir");
        std::fs::write(dir.join("a").join("b"), "b body").expect("static fixture file");
        for regime in [Regime::Windows, Regime::Unix] {
            let (status, body) = serve_static_dir(&dir, regime, "/static/a//b").await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{regime:?}");
            assert!(body.is_empty(), "{regime:?}: {body:?}");
            let (status, body) = serve_static_dir(&dir, regime, "/static/a/b").await;
            assert_eq!(status, axum::http::StatusCode::OK, "{regime:?}");
            assert_eq!(body, "b body", "{regime:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn static_mount_refuses_a_malformed_url_before_the_file_service() {
        // Prove the refusals: the file service never decodes a path or query
        // the strict core refused.
        for uri in [
            "/static/%zz",
            "/static/%C0%AF",
            "/static/hello%C3.txt",
            "/static/hello.txt?q=%zz",
        ] {
            let (status, body) = serve_static(uri).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{uri:?}");
            assert_eq!(body, "Bad Request", "{uri:?} must not echo the request");
        }
        let (status, body) = serve_static("/static/hello.txt").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "hi");
    }

    /// Prove the refusal: a path a mount re-bases with a leading empty segment
    /// (`/static//hello.txt`) reaches no file, though `hello.txt` exists.
    #[tokio::test]
    async fn static_mount_refuses_a_rest_led_by_an_empty_segment() {
        for uri in [
            "/static//hello.txt",
            "/static///hello.txt",
            "/%73tatic//hello.txt",
        ] {
            let (status, body) = serve_static(uri).await;
            assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "{uri:?}");
            assert!(body.is_empty(), "{uri:?}: {body:?}");
        }
        let (status, body) = serve_static("/static/hello.txt").await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body, "hi");
    }

    /// Prove the refusal: the static gate judges the listener's parse, so a
    /// request whose URI text names a served file but whose parse names
    /// another path reaches no file.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed paths parse and fixed requests build
    async fn static_gate_judges_the_listener_parse_not_the_uri() {
        use tower::ServiceExt;
        let dir = static_fixture_dir("strict-static-parse");
        std::fs::write(dir.join("hello.txt"), "hi").expect("static fixture file");
        let request = |parsed: &str| {
            let mut wire = axum::http::Request::builder()
                .method("GET")
                .uri("/hello.txt")
                .body(axum::body::Body::empty())
                .expect("test request builds");
            wire.extensions_mut().insert(StrictUrl {
                #[cfg(feature = "web")]
                spelling: Spelling::Canonical,
                path: crate::encoding::RequestPath::parse(parsed).expect("the path parses"),
                query: Arc::new(HashMap::new()),
                headers: Arc::new(
                    crate::http_header::RequestHeaders::parse(&axum::http::HeaderMap::new())
                        .expect("no headers fold"),
                ),
            });
            wire
        };
        let serve = |parsed: &'static str| {
            let files = strict_serve_dir_with(dir.clone(), crate::path_core::HOST);
            async move {
                match files.oneshot(request(parsed)).await {
                    Ok(r) => r.status(),
                    Err(e) => match e {},
                }
            }
        };
        for parsed in ["/other.txt", "/", "/hello.txt/x"] {
            assert_eq!(
                serve(parsed).await,
                axum::http::StatusCode::NOT_FOUND,
                "{parsed}"
            );
        }
        assert_eq!(serve("/hello.txt").await, axum::http::StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Serve `uri` through `CanonicalUrl` over raw axum routes and a fallback
    /// that do no URL check of their own, each answering with the target it
    /// saw. Returns the status, the body and how many times an inner handler ran.
    async fn serve_gated(uri: &str) -> (axum::http::StatusCode, String, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;
        let runs = Arc::new(AtomicUsize::new(0));
        let seen = |name: &'static str, runs: Arc<AtomicUsize>| {
            move |uri: axum::http::Uri, strict: Option<axum::Extension<StrictUrl>>| async move {
                runs.fetch_add(1, Ordering::SeqCst);
                // The spelling is a web-tier fact; a server-only build sees the parse alone.
                #[cfg(feature = "web")]
                let spelling = strict.map(|axum::Extension(s)| s.spelling());
                #[cfg(not(feature = "web"))]
                let spelling = strict.map(|_| "parsed");
                format!("{name} {uri} {spelling:?}")
            }
        };
        let inner = axum::Router::new()
            .route(
                "/raw/*rest",
                axum::routing::get(seen("route", Arc::clone(&runs))),
            )
            .route("/api", axum::routing::get(seen("api", Arc::clone(&runs))))
            .route("/a/b", axum::routing::get(seen("a/b", Arc::clone(&runs))))
            .fallback(seen("fallback", Arc::clone(&runs)));
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(axum::body::Body::empty())
            .expect("test request builds");
        let resp = match CanonicalUrl::new(inner).oneshot(wire).await {
            Ok(r) => r,
            Err(e) => match e {},
        };
        let status = resp.status();
        let body = axum_body_string(resp).await;
        (status, body, runs.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn canonical_url_refuses_a_malformed_url_before_any_route_or_fallback() {
        // Prove the refusals of the listener's URL service on its own: the
        // inner routes and fallback carry no URL check, so only the service
        // stands between them and a malformed path or query.
        // A path over the component ceiling never reaches this service: the
        // request target is bounded far below it by `http`'s own URI limit,
        // and `canonical_path` refuses its growth past the ceiling itself.
        for uri in [
            "/raw/%zz",
            "/raw/a%C3/%A9",
            "/raw/x?q=%zz",
            "/elsewhere/%C0%AF",
            "/elsewhere?%C3=1",
            "/%zz",
            "/%",
            "/no/such/route/%4",
        ] {
            let (status, body, runs) = serve_gated(uri).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{uri:?}");
            assert_eq!(body, "Bad Request", "{uri:?} must not echo the request");
            assert_eq!(runs, 0, "{uri:?} must never reach a route or fallback");
        }
    }

    /// A request no handler matches reaches the mount whose prefix is the
    /// longest whole-segment prefix of its decoded path, its URI and its
    /// listener parse re-based below that prefix; a handler under a mount's
    /// prefix shadows the mount on its own path.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed prefixes parse and fixed requests build
    async fn a_mount_serves_by_longest_prefix_below_its_prefix() {
        use tower::ServiceExt;
        let echo = |name: &'static str| {
            axum::Router::new().fallback(
                move |strict: Option<axum::Extension<StrictUrl>>, uri: axum::http::Uri| async move {
                    let served = strict.map_or_else(
                        || "unparsed".to_owned(),
                        |url| {
                            url.path
                                .canonical()
                                .map_or_else(|_| "too long".to_owned(), |c| c.as_str().to_owned())
                        },
                    );
                    format!("{name} {served} {uri}")
                },
            )
        };
        let base = |raw: &str| crate::encoding::MountBase::parse(raw).expect("base parses");
        let table = MountTable::new(vec![
            (base(""), echo("root")),
            (base("/billing"), echo("billing")),
            (base("/billing/admin"), echo("admin")),
        ]);
        let app = behind_listener(table.below(
            axum::Router::new().route("/billing/health", axum::routing::get(|| async { "health" })),
        ));
        for (uri, want) in [
            ("/billing", "billing / /"),
            ("/billing/", "billing / /"),
            ("/billing/x/", "billing /x/ /x/"),
            ("/%62illing/%61/b", "billing /a/b /a/b"),
            ("/billing/admin/x?q=%7a", "admin /x /x?q=%7a"),
            ("/billing/adminx", "billing /adminx /adminx"),
            ("/billingx", "root /billingx /billingx"),
            ("/", "root / /"),
            ("/billing/health", "health"),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("test request builds"),
                )
                .await
                .expect("router responds");
            assert_eq!(axum_body_string(resp).await, want, "{uri}");
        }
    }

    /// A request no handler matches and no mount's prefix holds is a 404.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: fixed prefixes parse and fixed requests build
    async fn a_path_below_no_mount_is_not_found() {
        use tower::ServiceExt;
        let base = crate::encoding::MountBase::parse("/billing").expect("base parses");
        let mounted = axum::Router::new().fallback(|| async { "billing" });
        let app =
            behind_listener(MountTable::new(vec![(base, mounted)]).below(axum::Router::new()));
        for uri in ["/", "/billingx", "/other/billing"] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("test request builds"),
                )
                .await
                .expect("router responds");
            assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND, "{uri}");
        }
    }

    #[cfg(feature = "web")]
    #[tokio::test]
    async fn canonical_url_routes_every_spelling_of_a_path_as_its_canonical_one() {
        for (uri, want) in [
            ("/raw/a%20b", "route /raw/a%20b Some(Canonical)"),
            ("/raw/a%2Fb?q=a+b", "route /raw/a%2Fb?q=a+b Some(Canonical)"),
            ("/elsewhere", "fallback /elsewhere Some(Canonical)"),
            ("/api", "api /api Some(Canonical)"),
            ("/%61pi", "api /api Some(Respelled)"),
            ("/%61%70%69?x=%7a", "api /api?x=%7a Some(Respelled)"),
            ("//api", "api /api Some(Respelled)"),
            ("/caf%c3%a9", "fallback /caf%C3%A9 Some(Respelled)"),
            ("/raw/a+b@c", "route /raw/a%2Bb%40c Some(Respelled)"),
            ("/a/b", "a/b /a/b Some(Canonical)"),
            ("/%61/%62", "a/b /a/b Some(Respelled)"),
            // An escaped `/` stays inside its segment: one segment, not `/a/b`.
            ("/a%2Fb", "fallback /a%2Fb Some(Canonical)"),
            ("/a%2fb", "fallback /a%2Fb Some(Respelled)"),
            // A decoded `:` or `*` is escaped, never read as a router sigil.
            ("/raw/%3Ax", "route /raw/%3Ax Some(Canonical)"),
            ("/raw/:x", "route /raw/%3Ax Some(Respelled)"),
        ] {
            let (status, body, runs) = serve_gated(uri).await;
            assert_eq!(status, axum::http::StatusCode::OK, "{uri:?}");
            assert_eq!(body, want, "{uri:?}");
            assert_eq!(runs, 1, "{uri:?}");
        }
    }

    #[tokio::test]
    async fn build_request_stores_canonical_header_keys() {
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .header("x-trace-id", "abc123")
            .header("content-type", "text/plain")
            .body(axum::body::Body::empty())
            .expect("test request builds");
        let built = routed_build("/", wire).await;
        assert!(matches!(built, Some(Ok(_))), "a routed request must build");
        let Some(Ok(req)) = built else {
            panic!("a routed request must build");
        };
        assert_eq!(
            req.headers.get("X-Trace-Id").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(
            req.headers.get("Content-Type").map(String::as_str),
            Some("text/plain")
        );
        // The verbatim lower-cased key must NOT be present (canonical only).
        assert!(!req.headers.contains_key("x-trace-id"));
        assert!(matches!(
            server_header("X-TRACE-ID".to_string(), req),
            IpeMaybe::Just(ref v) if v == "abc123"
        ));
    }

    #[test]
    fn build_routes_and_response() {
        // Validate the crux: a Ipê-shaped handler closure boxes into a Route.
        let r: ServerRoute = server_get::<String, _>("/".to_string(), |_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("hi".to_string()))))
                as IpeTask<String, ServerResponse>
        });
        assert_eq!(r.method, "GET");
        assert!(matches!(r.target, RouteTarget::Handler(_)));
        let resp = server_with_status(404, server_text("nope".to_string()));
        assert_eq!(resp.status, 404);
    }

    async fn axum_body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    }

    // A dev surface (dev build, loopback listener) emits the banner;
    // `inject_dev_banner` runs on every text/html buffered response.
    #[cfg(feature = "dev-posture")]
    #[tokio::test]
    async fn dev_posture_pin_to_axum_response_injects_dev_banner_before_body_close() {
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
        crate::telemetry::record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let ipe = server_html("<html><body><h1>hi</h1></body></html>".to_string());
        let out = axum_body_string(to_axum_response(ipe, RequestStreams::new())).await;
        assert!(
            out.contains(r#"<a id="__ipe-dev-console""#),
            "banner must be injected: {out}"
        );
        let banner_at = out
            .find(r#"<a id="__ipe-dev-console""#)
            .expect("banner present");
        let body_close = out.rfind("</body>").expect("</body> present");
        assert!(
            banner_at < body_close,
            "banner must sit before </body>: {out}"
        );
    }

    // A release binary under `ENV=dev` on a loopback listener has no dev
    // surface, so its HTML responses never carry the console banner.
    #[cfg(not(feature = "dev-posture"))]
    #[tokio::test]
    async fn to_axum_response_omits_dev_banner_on_release_under_env_dev() {
        crate::system::locked_set_var("ENV", "dev");
        crate::telemetry::record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let html = "<html><body><h1>hi</h1></body></html>";
        let out = axum_body_string(to_axum_response(
            server_html(html.to_string()),
            RequestStreams::new(),
        ))
        .await;
        crate::system::locked_remove_var("ENV");
        assert_eq!(out, html, "release HTML must be verbatim");
    }

    #[tokio::test]
    async fn to_axum_response_leaves_non_html_untouched() {
        // JSON / plain-text responses never get the banner (only text/html).
        let ipe = server_json(r#"{"ok":true}"#.to_string());
        let out = axum_body_string(to_axum_response(ipe, RequestStreams::new())).await;
        assert_eq!(out, r#"{"ok":true}"#, "non-html body must be verbatim");

        let ipe_text = server_text("plain body</body>".to_string());
        let out_text = axum_body_string(to_axum_response(ipe_text, RequestStreams::new())).await;
        assert_eq!(
            out_text, "plain body</body>",
            "text/plain body must be verbatim even with a </body> substring"
        );
    }

    #[test]
    fn origin_glob_matching() {
        assert!(ws_origin_matches(
            "https://app.example.com",
            "https://app.example.com"
        ));
        assert!(!ws_origin_matches(
            "https://app.example.com",
            "https://evil.com"
        ));
        assert!(ws_origin_matches(
            "https://*.example.com",
            "https://app.example.com"
        ));
        assert!(ws_origin_matches(
            "https://*.example.com",
            "https://a.b.example.com"
        ));
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "https://example.com"
        ));
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "http://app.example.com"
        ));
        assert!(ws_origin_matches("*", "anything://x"));
        assert!(ws_origin_matches("*.local", "x.local"));
        assert!(!ws_origin_matches("*.local", "x.remote"));
        // CSWSH glob-bypass: the trusted suffix must not be reachable behind a
        // path / userinfo / query delimiter smuggled through the `*`.
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "https://evil.com/.example.com"
        ));
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "https://evil.com@x.example.com"
        ));
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "https://evil.com?.example.com"
        ));
        assert!(!ws_origin_matches(
            "https://*.example.com",
            "https://evil.com#.example.com"
        ));
        // A trailing `*` is an explicit allow-all of the remainder (opt-in).
        assert!(ws_origin_matches(
            "https://app.example.com*",
            "https://app.example.com/anything"
        ));
    }

    fn mk_ws_req(headers: &[(&str, &str)]) -> ServerRequest {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.to_string(), v.to_string());
        }
        ServerRequest {
            method: "GET".to_string(),
            path: "/ws".to_string(),
            body: String::new(),
            headers: h,
            params: HashMap::new(),
            query: HashMap::new(),
            cookies: HashMap::new(),
            remoteAddr: String::new(),
        }
    }

    #[test]
    fn ws_cross_origin_detection() {
        assert!(ws_cross_origin(&mk_ws_req(&[
            ("origin", "https://evil.example"),
            ("host", "victim.example:8000"),
        ])));
        assert!(!ws_cross_origin(&mk_ws_req(&[
            ("origin", "https://victim.example:8000"),
            ("host", "victim.example:8000"),
        ])));
        // No Origin header at all → not flagged (non-browser client).
        assert!(!ws_cross_origin(&mk_ws_req(&[("host", "victim.example")])));
        // Backlog port-mismatch fix: an implicit-default-port Origin against
        // an explicit-default-port Host is the SAME origin, not a mismatch.
        assert!(!ws_cross_origin(&mk_ws_req(&[
            ("origin", "https://victim.example"),
            ("host", "victim.example:443"),
        ])));
    }

    #[tokio::test]
    async fn ws_upgrade_rejects_cross_origin_without_allowlist() {
        // The CSWSH default-deny path: `ENV=dev` on a loopback listener, empty
        // originPatterns, cross-origin Origin/Host pair. A dev surface falls
        // back to the same-origin check; a release binary refuses outright.
        crate::system::locked_set_var("ENV", "dev");
        crate::system::locked_remove_var("IPE_ENV");
        crate::telemetry::record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let cfg = ws_server_default_cfg::<String>();
        let req = mk_ws_req(&[
            ("origin", "https://evil.example"),
            ("host", "victim.example"),
        ]);
        // No WS_UPGRADER task-local is set in a plain unit test, so a request
        // that PASSES the origin check would hit the `None => 400` upgrader
        // branch instead of 403 — the origin check must short-circuit before
        // that point for this assertion to distinguish the two paths.
        let result = server_web_socket_upgrade::<String>(req, cfg).await;
        crate::system::locked_remove_var("ENV");
        let IpeResult::Ok(r) = result else {
            assert!(matches!(result, IpeResult::Ok(_)), "upgrade returned Err");
            return;
        };
        assert_eq!(r.status, 403, "cross-origin WS upgrade must be rejected");
    }

    /// The status a same-origin upgrade with no allowlist gets under the
    /// given `ENV` / `IPE_ENV` (`None` = unset), on a loopback listener.
    async fn same_origin_ws_status(env: Option<&str>, ipe_env: Option<&str>) -> i64 {
        for (key, value) in [("ENV", env), ("IPE_ENV", ipe_env)] {
            match value {
                Some(v) => crate::system::locked_set_var(key, v),
                None => crate::system::locked_remove_var(key),
            }
        }
        crate::telemetry::record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let req = mk_ws_req(&[
            ("origin", "https://victim.example"),
            ("host", "victim.example"),
        ]);
        let result =
            server_web_socket_upgrade::<String>(req, ws_server_default_cfg::<String>()).await;
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
        let IpeResult::Ok(resp) = result else {
            assert!(matches!(result, IpeResult::Ok(_)), "upgrade returned Err");
            return 0;
        };
        resp.status
    }

    // The no-allowlist refusal is waived only by a dev surface: never on a
    // release binary, whatever dev marker `ENV`/`IPE_ENV` carry, even on a
    // loopback listener.
    #[tokio::test]
    async fn ws_origin_required_on_release_under_env_dev() {
        let refusal = Some((403, "websocket: origin allowlist required in production"));
        assert_eq!(ws_origin_decision(true, None), refusal);
        assert_eq!(ws_origin_decision(false, None), None);
        let surface = crate::telemetry::test_dev_surface();
        assert_eq!(ws_origin_decision(true, Some(&surface)), None);
        assert_eq!(ws_origin_decision(false, Some(&surface)), None);
        if !cfg!(feature = "dev-posture") {
            for (env, ipe_env) in [
                (None, None),
                (Some("dev"), None),
                (Some(""), Some("dev")),
                (Some("Development"), None),
                (None, Some("LOCAL")),
            ] {
                assert_eq!(
                    same_origin_ws_status(env, ipe_env).await,
                    403,
                    "{env:?} {ipe_env:?}"
                );
            }
        }
        assert_eq!(same_origin_ws_status(Some(""), Some("prod")).await, 403);
        assert_eq!(same_origin_ws_status(Some("staging"), None).await, 403);
    }

    // A dev build on a loopback listener passes a same-origin upgrade through
    // the origin check (400 = no real upgrader in this unit test, not 403).
    #[cfg(feature = "dev-posture")]
    #[tokio::test]
    async fn dev_posture_pin_ws_same_origin_passes_without_allowlist() {
        assert_eq!(same_origin_ws_status(None, None).await, 400);
        assert_eq!(same_origin_ws_status(Some(""), Some("dev")).await, 400);
        assert_eq!(same_origin_ws_status(Some("dev"), None).await, 400);
    }

    #[tokio::test]
    async fn ws_upgrade_rejects_when_at_capacity() {
        // Pre-fill the live-peer registry to the ceiling, then a valid
        // same-origin upgrade must be turned away with 503 BEFORE any id/channel
        // is minted — distinguished from the `400 no-upgrader` fall-through the
        // same-origin path would otherwise hit in a unit test. The allowlist
        // names the request's Origin, so the origin gate passes it.
        crate::system::locked_remove_var("IPE_WS_MAX_CONNECTIONS");
        let ceiling = usize::try_from(WS_MAX_CONNECTIONS_CEILING.default_value()).unwrap();
        {
            let mut reg = ws_registry().lock().unwrap_or_else(|e| e.into_inner());
            reg.clear();
            for i in 0..ceiling as i64 {
                let (tx, _rx) = tokio::sync::mpsc::channel::<WsOut>(1);
                reg.insert(i, tx);
            }
        }
        let mut cfg = ws_server_default_cfg::<String>();
        cfg.originPatterns = vec!["https://victim.example".to_owned()];
        let req = mk_ws_req(&[
            ("origin", "https://victim.example"),
            ("host", "victim.example"),
        ]);
        let result = server_web_socket_upgrade::<String>(req, cfg).await;
        // teardown FIRST: never leave dummy peers pinned for sibling tests,
        // even if the assertion below fails.
        ws_registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let IpeResult::Ok(r) = result else {
            panic!("expected Ok(503) at capacity, got Err");
        };
        assert_eq!(
            r.status, 503,
            "WS upgrade at capacity must be rejected with 503 before minting a slot"
        );
    }

    #[test]
    fn ws_max_connections_default_and_override() {
        crate::system::locked_remove_var("IPE_WS_MAX_CONNECTIONS");
        assert_eq!(ws_ceilings().map(|c| c.max_connections), Ok(1024));
        crate::system::locked_set_var("IPE_WS_MAX_CONNECTIONS", "7");
        let overridden = ws_ceilings().map(|c| c.max_connections);
        crate::system::locked_set_var("IPE_WS_MAX_CONNECTIONS", "0");
        let zero = ws_ceilings();
        crate::system::locked_remove_var("IPE_WS_MAX_CONNECTIONS");
        assert_eq!(overridden, Ok(7));
        assert!(zero.is_err(), "a zero connection ceiling must be refused");
    }

    #[test]
    fn listen_ceilings_default_override_and_zero() {
        crate::system::locked_remove_var("IPE_HTTP_REQUEST_TIMEOUT");
        crate::system::locked_remove_var("IPE_HTTP_MAX_INFLIGHT");
        assert_eq!(
            listen_ceilings(),
            Ok(ListenCeilings {
                request_timeout_secs: 30,
                max_inflight: 1024,
            })
        );
        crate::system::locked_set_var("IPE_HTTP_REQUEST_TIMEOUT", "5");
        crate::system::locked_set_var("IPE_HTTP_MAX_INFLIGHT", "16");
        let overridden = listen_ceilings();
        crate::system::locked_set_var("IPE_HTTP_REQUEST_TIMEOUT", "0");
        let zero_timeout = listen_ceilings();
        crate::system::locked_remove_var("IPE_HTTP_REQUEST_TIMEOUT");
        crate::system::locked_set_var("IPE_HTTP_MAX_INFLIGHT", "0");
        let zero_inflight = listen_ceilings();
        crate::system::locked_remove_var("IPE_HTTP_MAX_INFLIGHT");
        assert_eq!(
            overridden,
            Ok(ListenCeilings {
                request_timeout_secs: 5,
                max_inflight: 16,
            })
        );
        assert!(zero_timeout.is_err_and(|r| r.name() == "IPE_HTTP_REQUEST_TIMEOUT"));
        assert!(zero_inflight.is_err_and(|r| r.name() == "IPE_HTTP_MAX_INFLIGHT"));
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn a_malformed_auth_ceiling_refuses_listen() {
        for (name, raw) in [
            ("IPE_AUTH_MAX_LIFETIME", "8h"),
            ("IPE_AUTH_SLIDE_WINDOW", "0"),
            ("IPE_REVOCATION_CAPACITY", " 1024"),
        ] {
            crate::system::locked_set_var(name, raw);
            let refused = listen_ceilings();
            crate::system::locked_remove_var(name);
            assert!(
                refused.is_err_and(|r| r.name() == name),
                "{name}={raw:?} must refuse Server.listen"
            );
        }
    }

    #[tokio::test]
    async fn serve_times_out_slow_handler() {
        // The same layer stack `server_listen` applies must turn a handler that
        // sleeps past the deadline into a timeout (408), proving the slowloris
        // ceiling is on the served path — not merely configured.
        use tower::ServiceExt;
        crate::system::locked_set_var("IPE_HTTP_REQUEST_TIMEOUT", "1");
        let ceilings = listen_ceilings();
        crate::system::locked_remove_var("IPE_HTTP_REQUEST_TIMEOUT");
        let ListenCeilings {
            request_timeout_secs: timeout,
            max_inflight: inflight,
        } = ceilings.expect("the listen ceilings must resolve");
        let app: axum::Router = axum::Router::new()
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    "never"
                }),
            )
            .layer(tower::limit::GlobalConcurrencyLimitLayer::new(inflight))
            .layer(tower_http::timeout::TimeoutLayer::new(
                std::time::Duration::from_secs(timeout),
            ));
        let req = axum::http::Request::builder()
            .uri("/slow")
            .body(axum::body::Body::empty());
        let Ok(req) = req else {
            crate::system::locked_remove_var("IPE_HTTP_REQUEST_TIMEOUT");
            panic!("failed to build test request");
        };
        // `Router`'s `Service` error is `Infallible`, so the call is total.
        let served = app.oneshot(req).await;
        crate::system::locked_remove_var("IPE_HTTP_REQUEST_TIMEOUT");
        let resp = match served {
            Ok(r) => r,
            Err(e) => match e {},
        };
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::REQUEST_TIMEOUT,
            "a handler slower than the deadline must resolve to 408"
        );
    }

    #[test]
    fn query_and_cookies() {
        let parsed = parse_query(Some("a=1&b=two%20words&a=ignored&flag"));
        assert!(parsed.is_ok(), "a well-formed query must parse");
        let Ok(q) = parsed else {
            panic!("a well-formed query must parse");
        };
        assert_eq!(q.get("a").map(String::as_str), Some("1")); // first value wins
        assert_eq!(q.get("b").map(String::as_str), Some("two words"));
        assert_eq!(q.get("flag").map(String::as_str), Some(""));
        assert!(parse_query(None).is_ok_and(|q| q.is_empty()));
        assert!(
            parse_query(Some("a=%zz")).is_err(),
            "a malformed query is refused whole"
        );

        let mut c = std::collections::HashMap::new();
        parse_cookies([b"sid=abc; theme=dark".as_slice()], &mut c);
        assert_eq!(c.get("sid").map(String::as_str), Some("abc"));
        assert_eq!(c.get("theme").map(String::as_str), Some("dark"));
    }

    #[test]
    fn max_body_env_override() {
        crate::system::locked_remove_var("IPE_WEB_MAX_BODY_BYTES");
        assert_eq!(max_body(), Ok(32 * 1024 * 1024));
        crate::system::locked_set_var("IPE_WEB_MAX_BODY_BYTES", "1024");
        let overridden = max_body();
        crate::system::locked_set_var("IPE_WEB_MAX_BODY_BYTES", "0");
        let zero = max_body();
        crate::system::locked_remove_var("IPE_WEB_MAX_BODY_BYTES");
        assert_eq!(overridden, Ok(1024));
        assert!(zero.is_err(), "a zero body ceiling must be refused");
    }

    #[tokio::test]
    async fn two_set_cookie_headers_both_survive() {
        let mut r = server_text("ok".to_string());
        r = server_with_cookie(cookie("a", "1"), r);
        r = server_with_cookie(cookie("b", "2"), r);
        let resp = to_axum_response(r, RequestStreams::new());
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .collect();
        assert_eq!(cookies.len(), 2, "both Set-Cookie lines must survive");
    }

    /// The cookie `Server.cookie name value` builds for a non-empty `name`.
    #[allow(clippy::expect_used)] // fixture: every caller passes a non-empty name
    fn cookie(name: &str, value: &str) -> ServerCookie {
        let built = match server_cookie(name.to_owned(), value.to_owned()) {
            IpeResult::Ok(c) => Some(c),
            IpeResult::Err(_) => None,
        };
        built.expect("a non-empty cookie name")
    }

    /// The parsed cookie name for a non-empty `raw`.
    #[allow(clippy::expect_used)] // fixture: every caller passes a non-empty name
    fn parsed_name(raw: &str) -> CookieName {
        CookieName::parse(raw).expect("a non-empty cookie name")
    }

    /// The `Set-Cookie` lines of `r` once it is an HTTP response.
    fn set_cookie_lines(r: ServerResponse) -> Vec<String> {
        to_axum_response(r, RequestStreams::new())
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_owned))
            .collect()
    }

    /// RFC 6265 `cookie-octet`, written out independently of the encoder's set.
    const fn is_cookie_octet(b: u8) -> bool {
        matches!(b, 0x21 | 0x23..=0x2B | 0x2D..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E)
    }

    /// RFC 7230 `tchar`, written out independently of the encoder's set.
    const fn is_tchar(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    }

    #[test]
    fn cookie_value_encodes_every_byte_outside_cookie_octet() {
        for (raw, encoded) in [
            ("é", "%C3%A9"),
            (";", "%3B"),
            (",", "%2C"),
            (" ", "%20"),
            ("\t", "%09"),
            ("\"", "%22"),
            ("\\", "%5C"),
            ("a\r\nSet-Cookie: x=y", "a%0D%0ASet-Cookie:%20x=y"),
            ("\u{7f}", "%7F"),
            ("😀", "%F0%9F%98%80"),
            ("%", "%25"),
            ("%41", "%2541"),
        ] {
            assert_eq!(CookieValue::encode(raw).as_str(), encoded, "value {raw:?}");
        }
    }

    #[test]
    fn cookie_value_keeps_cookie_octets_byte_for_byte() {
        let octets: String = (0u8..=0x7F)
            .filter(|&b| is_cookie_octet(b) && b != b'%')
            .map(char::from)
            .collect();
        assert_eq!(CookieValue::encode(&octets).as_str(), octets);
        assert_eq!(CookieValue::encode("").as_str(), "");
    }

    #[test]
    fn cookie_name_encodes_every_byte_outside_token() {
        for (raw, encoded) in [
            ("a=b", "a%3Db"),
            ("sé", "s%C3%A9"),
            ("a b", "a%20b"),
            ("a;b", "a%3Bb"),
            ("(x)", "%28x%29"),
            ("%", "%25"),
            ("s%69d", "s%2569d"),
        ] {
            assert_eq!(parsed_name(raw).as_str(), encoded, "name {raw:?}");
            assert_eq!(parsed_name(raw).text(), raw, "name {raw:?}");
        }
        let tchars: String = (0u8..=0x7F)
            .filter(|&b| is_tchar(b) && b != b'%')
            .map(char::from)
            .collect();
        assert_eq!(parsed_name(&tchars).as_str(), tchars);
    }

    /// Every ASCII byte and non-ASCII text, in name and value, yields a line of
    /// grammar bytes that is a valid header value.
    #[test]
    fn set_cookie_from_any_text_is_a_valid_header_value() {
        let mut inputs: Vec<String> = (0u8..=0x7F).map(|b| char::from(b).to_string()).collect();
        inputs.extend(["é".to_owned(), "\u{2028}".to_owned(), "日本".to_owned()]);
        for raw in &inputs {
            let name = parsed_name(raw);
            let value = CookieValue::encode(raw);
            assert!(name.as_str().bytes().all(is_tchar), "name {raw:?}");
            assert!(value.as_str().bytes().all(is_cookie_octet), "value {raw:?}");
            let line = SetCookie::new(
                &name,
                &value,
                CookieAttributes {
                    path: CookiePath::root(),
                    http_only: true,
                    same_site: SameSite::Lax,
                    secure: true,
                    max_age_secs: Some(60),
                },
            );
            assert!(
                axum::http::HeaderValue::from_str(line.as_str()).is_ok(),
                "{line}"
            );
            assert_eq!(
                line.matches(';').count(),
                5,
                "no smuggled attribute: {line}"
            );
        }
    }

    /// A non-ASCII, `;`, `,`, whitespace or `"` value no longer fails the whole
    /// response: it is answered with the encoded cookie.
    #[tokio::test]
    async fn with_cookie_non_cookie_octet_value_keeps_the_response() {
        let r = server_with_cookie(
            cookie("sid", "é; a, b \"c\""),
            server_text("ok".to_string()),
        );
        let resp = to_axum_response(r, RequestStreams::new());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let cookies: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().map(str::to_owned))
            .collect();
        assert_eq!(cookies.len(), 1, "{cookies:?}");
        let Some(Ok(line)) = cookies.first() else {
            panic!("the Set-Cookie header must be visible ASCII: {cookies:?}");
        };
        assert!(
            line.starts_with("sid=%C3%A9%3B%20a%2C%20b%20%22c%22; Path=/; HttpOnly; SameSite=Lax"),
            "{line}"
        );
    }

    /// `SameSite=None` without `Secure` has no representation: the line
    /// carries `Secure` even when the caller's `secure` flag is off.
    #[test]
    fn same_site_none_always_renders_secure() {
        let line = SetCookie::new(
            &parsed_name("sid"),
            &CookieValue::encode("v"),
            CookieAttributes {
                path: CookiePath::root(),
                http_only: true,
                same_site: SameSite::None,
                secure: false,
                max_age_secs: None,
            },
        );
        assert_eq!(
            line.as_str(),
            "sid=v; Path=/; HttpOnly; SameSite=None; Secure"
        );
        let lax = SetCookie::new(
            &parsed_name("sid"),
            &CookieValue::encode("v"),
            CookieAttributes {
                path: CookiePath::root(),
                http_only: false,
                same_site: SameSite::Lax,
                secure: false,
                max_age_secs: Some(5),
            },
        );
        assert_eq!(lax.as_str(), "sid=v; Path=/; SameSite=Lax; Max-Age=5");
    }

    /// A `Path` value keeps every `av-octet`, encodes CTLs, `;` and non-ASCII,
    /// and always starts with `/`.
    #[test]
    fn cookie_path_encodes_every_byte_outside_av_octet() {
        for (raw, encoded) in [
            ("/", "/"),
            ("", "/"),
            ("/shop", "/shop"),
            ("shop", "/shop"),
            ("/a;b", "/a%3Bb"),
            ("/a\r\nSet-Cookie: x=y", "/a%0D%0ASet-Cookie: x=y"),
            ("/caf\u{e9}", "/caf%C3%A9"),
            ("/a b,c\"d", "/a b,c\"d"),
        ] {
            assert_eq!(CookiePath::encode(raw).as_str(), encoded, "path {raw:?}");
        }
        let line = SetCookie::new(
            &parsed_name("sid"),
            &CookieValue::encode("v"),
            CookieAttributes {
                path: CookiePath::encode("/a;Domain=evil.example\r\nX: y"),
                http_only: true,
                same_site: SameSite::Lax,
                secure: true,
                max_age_secs: None,
            },
        );
        assert!(
            axum::http::HeaderValue::from_str(line.as_str()).is_ok(),
            "{line}"
        );
        assert_eq!(
            line.matches(';').count(),
            4,
            "no smuggled attribute: {line}"
        );
    }

    /// An empty cookie name is an `InvalidInput` error, so no `Set-Cookie`
    /// line starts with `=`.
    #[tokio::test]
    async fn with_cookie_never_emits_nameless_line() {
        assert!(matches!(
            server_cookie(String::new(), "a=b".into()),
            IpeResult::Err(IpeError::Error(IpeErrorKind::InvalidInput, _))
        ));
        let mut names: Vec<String> = (0u8..=0x7F).map(|b| char::from(b).to_string()).collect();
        names.extend(["=".to_owned(), " ".to_owned(), "é".to_owned()]);
        for raw in &names {
            let lines = set_cookie_lines(server_with_cookie(
                cookie(raw, "v"),
                server_text("ok".to_owned()),
            ));
            assert_eq!(lines.len(), 1, "name {raw:?}: {lines:?}");
            for line in &lines {
                assert!(!line.starts_with('='), "name {raw:?}: {line}");
                let Some((wire, _)) = line.split_once('=') else {
                    panic!("name {raw:?}: the Set-Cookie line has no `=`: {line}");
                };
                assert!(!wire.is_empty(), "name {raw:?}: {line}");
                assert!(wire.bytes().all(is_tchar), "name {raw:?}: {line}");
            }
        }
    }

    /// Any name and value `Server.cookie` writes reads back unchanged through
    /// the request parser and `Server.getCookie`.
    #[tokio::test]
    async fn cookie_round_trips_through_get_cookie() {
        let mut texts: Vec<String> = (0u8..=0x7F).map(|b| char::from(b).to_string()).collect();
        texts.extend(
            [
                "%41", "%", "%%", "%ZZ", "é", "日本", "my sid", "\u{2028}", "😀", "a=b; c",
            ]
            .map(str::to_owned),
        );
        for name in &texts {
            for value in [name.as_str(), "", "%41", "é;%"] {
                let lines = set_cookie_lines(server_with_cookie(
                    cookie(name, value),
                    server_text("ok".to_owned()),
                ));
                assert_eq!(lines.len(), 1, "name {name:?}: {lines:?}");
                let Some((pair, _)) = lines.first().and_then(|l| l.split_once(';')) else {
                    panic!("name {name:?} value {value:?}: no `name=value;` pair in {lines:?}");
                };
                let mut jar = HashMap::new();
                parse_cookies([format!("other=1; {pair}").as_bytes()], &mut jar);
                let req = mk_req("GET", jar, HashMap::new());
                assert_eq!(
                    server_get_cookie(name.clone(), req),
                    IpeMaybe::Just(value.to_owned()),
                    "name {name:?} value {value:?} via {pair:?}"
                );
            }
        }
    }

    /// A `%` without two hex digits, or bytes that are not UTF-8, have no
    /// decoding: the cookie is absent, never a lossy value.
    #[test]
    fn undecodable_cookie_is_nothing() {
        for wire in ["%ZZ", "%C3", "%FF%FE", "%4", "%", "a%G1"] {
            assert_eq!(
                crate::http_header::cookie::decode(wire),
                None,
                "wire {wire:?}"
            );
        }
        assert_eq!(
            crate::http_header::cookie::decode("%C3%A9%25"),
            Some("é%".to_owned())
        );
        let mut jar = HashMap::new();
        parse_cookies(
            [b"a=%ZZ; b=%C3; c=%FF%FE; d=%4; e=ok; =v; s%69d=v".as_slice()],
            &mut jar,
        );
        assert_eq!(jar.len(), 1, "{jar:?}");
        assert_eq!(jar.get("e").map(String::as_str), Some("ok"));
        for name in ["a", "b", "c", "d", "", "sid", "s%69d"] {
            let req = mk_req("GET", jar.clone(), HashMap::new());
            assert_eq!(
                server_get_cookie(name.to_owned(), req),
                IpeMaybe::Nothing,
                "name {name:?}"
            );
        }
    }

    /// Every header lookup keys on the encoded name: a lookup by `ipe_sid`
    /// never matches a cookie whose wire name only decodes to it.
    #[test]
    fn request_cookie_keys_on_the_encoded_name() {
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_static("ipe%5Fsid=forged; my%20sid=a%3Bb"),
        );
        headers.append(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_static("ipe_sid=real; ipe_sid=second"),
        );
        assert_eq!(
            request_cookie(&headers, &parsed_name("ipe_sid")),
            Some("real".to_owned())
        );
        assert_eq!(
            request_cookie(&headers, &parsed_name("my sid")),
            Some("a;b".to_owned())
        );
        assert_eq!(request_cookie(&headers, &parsed_name("ipe%5Fsid")), None);
    }

    /// A lookup reads the session cookie beside a pair with a non-ASCII byte.
    #[test]
    fn request_cookie_reads_beside_a_non_ascii_pair() {
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_bytes(b"x=\x80; ipe_sid=real")
                .expect("obs-text is a valid header value"),
        );
        assert_eq!(
            request_cookie(&headers, &parsed_name("ipe_sid")),
            Some("real".to_owned())
        );
        assert_eq!(request_cookie(&headers, &parsed_name("x")), None);
    }

    /// A refused `IPE_WEB_FRAME_ANCESTORS` answers 500: no response ships with
    /// a header set missing its framing policy.
    #[test]
    fn response_refuses_a_refused_framing_policy() {
        let refused = to_axum_response_with(
            server_text("ok".to_owned()),
            RequestStreams::new(),
            Err(crate::telemetry::FrameAncestorsRefusal::Blank),
        );
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(refused.headers().get("x-frame-options").is_none());
        let framed = to_axum_response_with(
            server_text("ok".to_owned()),
            RequestStreams::new(),
            Ok(vec![("x-frame-options", "SAMEORIGIN".to_owned())]),
        );
        assert_eq!(framed.status(), axum::http::StatusCode::OK);
        assert_eq!(
            framed
                .headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("SAMEORIGIN")
        );
    }

    /// The `content-security-policy` the `Response` profile sends under this
    /// process's framing configuration.
    fn response_policy() -> String {
        crate::csp::ContentSecurityPolicy::for_guard(
            &crate::csp::Guarded::Response,
            crate::telemetry::frame_ancestors(),
        )
        .header_value()
    }

    /// An HTML handler response that sets no policy gets the `Response`
    /// profile through the production header path.
    #[test]
    fn server_default_csp_present() {
        let resp = to_axum_response(server_html("<p>hi</p>".to_owned()), RequestStreams::new());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let want = response_policy();
        assert_eq!(
            single_header(&resp, "content-security-policy"),
            Some(want.as_str())
        );
        assert!(
            want.starts_with("default-src 'none'; script-src 'self'; "),
            "{want}"
        );
        assert_eq!(
            single_header(&resp, "x-content-type-options"),
            Some("nosniff")
        );
    }

    /// A handler-set `content-security-policy` is kept verbatim, and no second
    /// policy header is added beside it.
    #[test]
    fn server_handler_csp_wins() {
        let own = "default-src 'self'; script-src 'self' https://cdn.example";
        let mut r = server_html("<p>hi</p>".to_owned());
        r.headers
            .insert("Content-Security-Policy".to_owned(), own.to_owned());
        let resp = to_axum_response(r, RequestStreams::new());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get_all("content-security-policy")
                .iter()
                .count(),
            1
        );
        assert_eq!(single_header(&resp, "content-security-policy"), Some(own));
    }

    /// An HTML file served from a static directory carries the `Response`
    /// profile, and so do its missing-file 404 and malformed-URL 400.
    #[tokio::test]
    async fn static_dir_gets_csp() {
        use tower::ServiceExt;
        let dir = static_fixture_dir("static-csp");
        std::fs::write(dir.join("page.html"), "<p>hi</p>").expect("static fixture file");
        let want = response_policy();
        for (uri, status) in [
            ("/static/page.html", axum::http::StatusCode::OK),
            ("/static/missing.html", axum::http::StatusCode::NOT_FOUND),
            ("/static/%zz", axum::http::StatusCode::BAD_REQUEST),
        ] {
            let base = crate::encoding::MountBase::parse("/static").expect("the prefix parses");
            let files = axum::Router::new()
                .fallback_service(strict_serve_dir_with(dir.clone(), crate::path_core::HOST));
            let app =
                behind_listener(MountTable::new(vec![(base, files)]).below(axum::Router::new()));
            let wire = axum::http::Request::builder()
                .method("GET")
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("test request builds");
            let resp = match app.oneshot(wire).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            assert_eq!(resp.status(), status, "{uri}");
            assert_eq!(
                single_header(&resp, "content-security-policy"),
                Some(want.as_str()),
                "{uri}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Each refused framing class answers 500 on a handler response, and a
    /// refused set never reaches a static or console response either.
    #[test]
    fn frame_ancestors_refusal_answers_500() {
        for raw in ["'self'; script-src *", "a, b", "a\rb", "a\u{1}b", " \t "] {
            let parsed = crate::telemetry::FrameAncestors::parse(raw);
            assert!(parsed.is_err(), "{raw:?}");
            if let Err(refusal) = parsed {
                let resp = to_axum_response_with(
                    server_html("<p>hi</p>".to_owned()),
                    RequestStreams::new(),
                    Err(refusal),
                );
                assert_eq!(
                    resp.status(),
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "{raw:?}"
                );
                assert!(resp.headers().get("content-security-policy").is_none());
                let resp = with_security_headers(
                    axum::response::IntoResponse::into_response("ok"),
                    Err(refusal),
                );
                assert_eq!(
                    resp.status(),
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "{raw:?}"
                );
            }
        }
    }

    /// A header the response already carries keeps its value; the default
    /// fills only the header the response lacks.
    #[test]
    fn security_headers_keep_a_header_the_response_set() {
        type Defaults =
            Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>;
        let defaults = || -> Defaults {
            Ok(vec![
                ("content-security-policy", "default-src 'none'".to_owned()),
                ("x-frame-options", "SAMEORIGIN".to_owned()),
            ])
        };
        let mut set = axum::response::IntoResponse::into_response("ok");
        set.headers_mut().insert(
            axum::http::header::CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static("img-src 'self'"),
        );
        let kept = with_security_headers(set, defaults());
        assert_eq!(kept.status(), axum::http::StatusCode::OK);
        assert_eq!(
            single_header(&kept, "content-security-policy"),
            Some("img-src 'self'")
        );
        assert_eq!(single_header(&kept, "x-frame-options"), Some("SAMEORIGIN"));

        let filled = with_security_headers(
            axum::response::IntoResponse::into_response("ok"),
            defaults(),
        );
        assert_eq!(filled.status(), axum::http::StatusCode::OK);
        assert_eq!(
            single_header(&filled, "content-security-policy"),
            Some("default-src 'none'")
        );
        assert_eq!(
            single_header(&filled, "x-frame-options"),
            Some("SAMEORIGIN")
        );
    }

    /// The `InvalidInput` message of a refused `Server.withHeader`, or `None`
    /// when the header was accepted.
    fn with_header_refusal(name: &str, value: &str) -> Option<String> {
        match server_with_header(
            name.to_owned(),
            value.to_owned(),
            server_text("ok".to_owned()),
        ) {
            IpeResult::Ok(_) => None,
            IpeResult::Err(IpeError::Error(IpeErrorKind::InvalidInput, info)) => Some(info.message),
            IpeResult::Err(IpeError::Error(_, info)) => {
                Some(format!("wrong kind: {}", info.message))
            }
        }
    }

    /// A header value with CR/LF, a name that is not a `token`, and
    /// `Set-Cookie` in any case are refused; a valid header is kept.
    #[tokio::test]
    async fn with_header_refuses_unrepresentable_headers() {
        for (name, value) in [
            ("X-Ok", "a\r\nSet-Cookie: x=y"),
            ("X-Ok", "a\nb"),
            ("X-Ok", "caf\u{e9}"),
            ("X Bad", "v"),
            ("X-Bad:", "v"),
            ("", "v"),
        ] {
            let refusal = with_header_refusal(name, value);
            assert!(
                refusal
                    .as_deref()
                    .is_some_and(|m| m.starts_with("Server.withHeader:")),
                "{name:?}: {value:?} -> {refusal:?}"
            );
        }
        for name in ["Set-Cookie", "set-cookie", "SET-COOKIE"] {
            let refusal = with_header_refusal(name, "sid=1");
            assert!(
                refusal
                    .as_deref()
                    .is_some_and(|m| m.contains("Server.withCookie")),
                "{name:?} -> {refusal:?}"
            );
        }
        for name in [
            "Content-Length",
            "content-length",
            "Transfer-Encoding",
            "TRANSFER-ENCODING",
        ] {
            let refusal = with_header_refusal(name, "5");
            assert!(
                refusal
                    .as_deref()
                    .is_some_and(|m| m.contains("set by the server")),
                "{name:?} -> {refusal:?}"
            );
        }
        assert_eq!(with_header_refusal("X-Frame-Options", "DENY"), None);
        let IpeResult::Ok(r) = server_with_header(
            "X-Frame-Options".to_owned(),
            "DENY".to_owned(),
            server_text("ok".to_owned()),
        ) else {
            panic!("`X-Frame-Options: DENY` must be accepted by `withHeader`");
        };
        let resp = to_axum_response(r, RequestStreams::new());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
    }

    /// A raw header a `Response` record update carries past `withHeader` is
    /// parsed again: a `Set-Cookie` or CR/LF header answers 500, never a line.
    #[tokio::test]
    async fn to_axum_response_refuses_a_raw_unrepresentable_header() {
        for (name, value) in [
            ("Set-Cookie", "sid=forged; Path=/"),
            ("set-cookie", "sid=forged"),
            ("X-Ok", "a\r\nSet-Cookie: sid=forged"),
            ("X Bad", "v"),
            ("Content-Length", "0"),
            ("transfer-encoding", "chunked"),
        ] {
            let mut r = server_text("ok".to_owned());
            r.headers.insert(name.to_owned(), value.to_owned());
            let resp = to_axum_response(r, RequestStreams::new());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{name:?}: {value:?}"
            );
            assert!(
                resp.headers().get(axum::http::header::SET_COOKIE).is_none(),
                "{name:?}: {value:?}"
            );
        }
    }

    /// A cookie line with no header representation answers 500, never a
    /// response that drops the cookie or splits the line.
    #[tokio::test]
    async fn to_axum_response_refuses_an_unrepresentable_cookie_line() {
        let mut r = server_text("ok".to_owned());
        r.cookies
            .push(SetCookie::unchecked_for_test("sid=a\r\nX-Injected: 1"));
        let resp = to_axum_response(r, RequestStreams::new());
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(axum::http::header::SET_COOKIE).is_none());
        assert!(resp.headers().get("x-injected").is_none());
    }

    /// A `stream` response whose handler emits nothing, beside the table of
    /// the request that registered it.
    async fn streamed(content_type: &str) -> (ServerResponse, RequestStreams) {
        let task = server_stream_stream::<IpeError, _>(content_type.to_owned(), |_w| {
            Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
        });
        let (result, streams) = crate::server_stream::in_stream_scope(task).await;
        let built = match result {
            IpeResult::Ok(r) => Some(r),
            IpeResult::Err(_) => None,
        };
        (built.expect("`stream` must build a response"), streams)
    }

    /// A `stream` task whose handler sets `ran` when it runs.
    fn flagged_stream(
        ran: Arc<std::sync::atomic::AtomicBool>,
    ) -> IpeTask<IpeError, ServerResponse> {
        server_stream_stream::<IpeError, _>("text/event-stream".to_owned(), move |_w| {
            ran.store(true, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
        })
    }

    /// The response of a fresh request whose handler registered
    /// `flagged_stream`, beside that request's table.
    async fn flagged(ran: &Arc<std::sync::atomic::AtomicBool>) -> (ServerResponse, RequestStreams) {
        let (result, streams) =
            crate::server_stream::in_stream_scope(flagged_stream(Arc::clone(ran))).await;
        let built = match result {
            IpeResult::Ok(r) => Some(r),
            IpeResult::Err(_) => None,
        };
        (built.expect("`stream` must build a response"), streams)
    }

    /// Whether `ran` is set once the runtime has had the chance to run a
    /// spawned stream handler.
    async fn ran_eventually(ran: &std::sync::atomic::AtomicBool) -> bool {
        for _ in 0..1024 {
            if ran.load(std::sync::atomic::Ordering::SeqCst) {
                return true;
            }
            tokio::task::yield_now().await;
        }
        ran.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The security headers `to_axum_response_with` is handed in these tests.
    fn framed_security()
    -> Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal> {
        Ok(vec![
            ("x-content-type-options", "nosniff".to_owned()),
            ("x-frame-options", "SAMEORIGIN".to_owned()),
        ])
    }

    /// The one value of header `name` in `resp`, or `None` for none or several.
    fn single_header<'a>(resp: &'a axum::response::Response, name: &str) -> Option<&'a str> {
        let mut all = resp.headers().get_all(name).iter();
        let first = all.next()?;
        if all.next().is_some() {
            return None;
        }
        first.to_str().ok()
    }

    /// A streamed response carries the framing and `nosniff` headers, its
    /// content type and the streaming hints; a handler header overrides a hint.
    #[tokio::test]
    async fn streamed_response_carries_the_security_headers() {
        let (mut r, streams) = streamed("text/event-stream").await;
        r.headers
            .insert("Cache-Control".to_owned(), "no-store".to_owned());
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(single_header(&resp, "x-frame-options"), Some("SAMEORIGIN"));
        assert_eq!(
            single_header(&resp, "x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(
            single_header(&resp, "content-type"),
            Some("text/event-stream")
        );
        assert_eq!(single_header(&resp, "x-accel-buffering"), Some("no"));
        assert_eq!(single_header(&resp, "cache-control"), Some("no-store"));
    }

    /// A streamed response sends every `Set-Cookie` line of its `cookies`.
    #[tokio::test]
    async fn streamed_response_emits_its_set_cookie_lines() {
        let (mut r, streams) = streamed("text/event-stream").await;
        r = server_with_cookie(cookie("a", "1"), r);
        r = server_with_cookie(cookie("b", "2"), r);
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let lines: Vec<_> = resp
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines.iter().any(|l| l.starts_with("a=1")), "{lines:?}");
        assert!(lines.iter().any(|l| l.starts_with("b=2")), "{lines:?}");
    }

    /// A refused `IPE_WEB_FRAME_ANCESTORS` answers 500 on a streamed response.
    #[tokio::test]
    async fn streamed_response_refuses_a_refused_framing_policy() {
        let (r, streams) = streamed("text/event-stream").await;
        let resp = to_axum_response_with(
            r,
            streams,
            Err(crate::telemetry::FrameAncestorsRefusal::Blank),
        );
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get("x-frame-options").is_none());
        assert!(resp.headers().get("x-accel-buffering").is_none());
    }

    /// A raw header with no representation is the same typed refusal on a
    /// buffered and a streamed head, and answers 500 on a streamed response.
    #[tokio::test]
    async fn buffered_and_streamed_heads_refuse_raw_headers_alike() {
        for (name, value) in [
            ("Set-Cookie", "sid=forged; Path=/"),
            ("set-cookie", "sid=forged"),
            ("X-Ok", "a\r\nSet-Cookie: sid=forged"),
            ("X-Ok", "a\nb"),
            ("X Bad", "v"),
            ("Content-Length", "0"),
            ("transfer-encoding", "chunked"),
        ] {
            let mut buffered = server_text("ok".to_owned());
            buffered.headers.insert(name.to_owned(), value.to_owned());
            for delivery in [ServerDelivery::Buffered, ServerDelivery::Streamed] {
                assert!(
                    matches!(
                        assemble_response_head(&buffered, delivery, framed_security()),
                        Err(response_head::HeadRefusal::Header)
                    ),
                    "{name:?}: {value:?} under {delivery:?}"
                );
            }
            let (mut r, streams) = streamed("text/event-stream").await;
            r.headers.insert(name.to_owned(), value.to_owned());
            let resp = to_axum_response_with(r, streams, framed_security());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{name:?}: {value:?}"
            );
            assert!(
                resp.headers().get(axum::http::header::SET_COOKIE).is_none(),
                "{name:?}: {value:?}"
            );
        }
    }

    /// Two handler headers naming one header in different cases are the same
    /// typed refusal on a buffered and a streamed head, and answer 500 on
    /// both deliveries: the head never depends on `HashMap` iteration order.
    #[tokio::test]
    async fn heads_refuse_two_spellings_of_one_header_name() {
        for [(first, first_value), (second, second_value)] in [
            [
                ("Content-Type", "text/html"),
                ("content-type", "text/plain"),
            ],
            [("X-Custom", "a"), ("x-CUSTOM", "b")],
        ] {
            let mut buffered = server_text("ok".to_owned());
            buffered
                .headers
                .insert(first.to_owned(), first_value.to_owned());
            buffered
                .headers
                .insert(second.to_owned(), second_value.to_owned());
            for delivery in [ServerDelivery::Buffered, ServerDelivery::Streamed] {
                assert!(
                    matches!(
                        assemble_response_head(&buffered, delivery, framed_security()),
                        Err(response_head::HeadRefusal::Header)
                    ),
                    "{first:?}/{second:?} under {delivery:?}"
                );
            }
            let resp = to_axum_response_with(buffered, RequestStreams::new(), framed_security());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{first:?}/{second:?}"
            );
            let (mut r, streams) = streamed("text/event-stream").await;
            r.headers.insert(first.to_owned(), first_value.to_owned());
            r.headers.insert(second.to_owned(), second_value.to_owned());
            let resp = to_axum_response_with(r, streams, framed_security());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{first:?}/{second:?}"
            );
            assert!(resp.headers().get("x-accel-buffering").is_none());
        }
    }

    /// `Server.withHeader` replaces a header of the same name in any case, so
    /// a response it builds holds one value per header name.
    #[test]
    fn with_header_replaces_a_header_of_the_same_name_in_any_case() {
        let set = |k: &str, v: &str, r: ServerResponse| {
            let built = match server_with_header(k.to_owned(), v.to_owned(), r) {
                IpeResult::Ok(r) => Some(r),
                IpeResult::Err(_) => None,
            };
            built.expect("a token name and a visible-ASCII value are a header")
        };
        let r = set("Location", "/b", server_redirect("/a".to_owned()));
        let r = set("X-Custom", "1", r);
        let r = set("x-custom", "2", r);
        assert_eq!(r.headers.len(), 2, "{:?}", r.headers);
        let resp = to_axum_response_with(r, RequestStreams::new(), framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
        assert_eq!(single_header(&resp, "location"), Some("/b"));
        assert_eq!(single_header(&resp, "x-custom"), Some("2"));
    }

    /// The response `middleware_with_cors` allowing `origins` makes of a
    /// `method` request carrying `origin`, whose handler set `headers`, as it
    /// is sent.
    async fn cors_tagged(
        origins: &[&str],
        method: &str,
        origin: Option<&str>,
        headers: &[(&str, &str)],
    ) -> axum::response::Response {
        let set: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let h = middleware_with_cors::<String, _>(
            origins.iter().map(|o| (*o).to_owned()).collect(),
            move |_req: ServerRequest| {
                let mut r = server_text("ok".into());
                for (k, v) in set.clone() {
                    r = match server_with_header(k, v, r) {
                        IpeResult::Ok(r) => r,
                        IpeResult::Err(e) => panic!("handler header refused: {e:?}"),
                    };
                }
                Box::pin(ready(ok_res::<String, _>(r))) as IpeTask<String, ServerResponse>
            },
        );
        cors_sent(&h, method, origin).await
    }

    /// What handler `h` answers a `method` request carrying `origin`, as it is
    /// sent.
    async fn cors_sent(
        h: &ServerHandler<String>,
        method: &str,
        origin: Option<&str>,
    ) -> axum::response::Response {
        let mut req_headers = HashMap::new();
        if let Some(o) = origin {
            req_headers.insert("Origin".to_owned(), o.to_owned());
        }
        let IpeResult::Ok(r) = h(mk_req(method, HashMap::new(), req_headers)).await else {
            panic!("the CORS middleware must pass the handler's response through");
        };
        to_axum_response_with(r, RequestStreams::new(), framed_security())
    }

    /// A handler's `Access-Control-Allow-Origin` in any case is replaced by
    /// the middleware's grant: the sent head carries exactly one value.
    #[tokio::test]
    async fn cors_replaces_a_handler_allow_origin_in_any_case() {
        for name in [
            "Access-Control-Allow-Origin",
            "ACCESS-CONTROL-ALLOW-ORIGIN",
            "access-control-allow-origin",
        ] {
            for (origins, granted) in [
                (&["https://a.example"][..], "https://a.example"),
                (&["*"][..], "*"),
            ] {
                let resp = cors_tagged(
                    origins,
                    "GET",
                    Some("https://a.example"),
                    &[(name, "https://evil.example")],
                )
                .await;
                assert_eq!(resp.status(), axum::http::StatusCode::OK, "{name}");
                assert_eq!(
                    single_header(&resp, "access-control-allow-origin"),
                    Some(granted),
                    "{name} / {origins:?}"
                );
            }
        }
    }

    /// A handler's `Vary` in any case is merged with `Origin` into one value,
    /// and a `Vary` already naming `Origin` is kept as is.
    #[tokio::test]
    async fn cors_merges_a_handler_vary_in_any_case_into_one_value() {
        let allowed = Some("https://a.example");
        for name in ["Vary", "VARY", "vary"] {
            let resp = cors_tagged(
                &["https://a.example"],
                "GET",
                allowed,
                &[(name, "Accept-Encoding")],
            )
            .await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{name}");
            assert_eq!(
                single_header(&resp, "vary"),
                Some("Accept-Encoding, Origin"),
                "{name}"
            );
            let resp =
                cors_tagged(&["https://a.example"], "GET", allowed, &[(name, "origin")]).await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{name}");
            assert_eq!(single_header(&resp, "vary"), Some("origin"), "{name}");
        }
        let resp = cors_tagged(&["https://a.example"], "GET", allowed, &[]).await;
        assert_eq!(single_header(&resp, "vary"), Some("Origin"));
    }

    /// Under an allowlist, a refused origin's response names `Origin` in `Vary`
    /// and carries no grant, so a shared cache never serves it to an allowed
    /// origin.
    #[tokio::test]
    async fn cors_refused_origin_varies_on_origin_without_a_grant() {
        let resp = cors_tagged(
            &["https://a.example"],
            "GET",
            Some("https://evil.example"),
            &[],
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(single_header(&resp, "vary"), Some("Origin"));
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    /// Under an allowlist, an absent or empty `Origin` is refused and still
    /// varies on `Origin`, an empty allowlist entry included.
    #[tokio::test]
    async fn cors_absent_or_empty_origin_varies_on_origin_without_a_grant() {
        for (origins, origin) in [
            (&["https://a.example"][..], None),
            (&["https://a.example"][..], Some("")),
            (&["", "https://a.example"][..], Some("")),
            (&["", "https://a.example"][..], None),
        ] {
            let resp = cors_tagged(origins, "GET", origin, &[]).await;
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::OK,
                "{origins:?} / {origin:?}"
            );
            assert_eq!(
                single_header(&resp, "vary"),
                Some("Origin"),
                "{origins:?} / {origin:?}"
            );
            assert!(
                resp.headers().get("access-control-allow-origin").is_none(),
                "{origins:?} / {origin:?}"
            );
        }
    }

    /// Under an allowlist, every preflight answer varies on `Origin`, and only
    /// an allowed origin's carries a grant.
    #[tokio::test]
    async fn cors_preflight_varies_on_origin_for_every_origin() {
        for (origin, granted) in [
            (Some("https://a.example"), Some("https://a.example")),
            (Some("https://evil.example"), None),
            (None, None),
        ] {
            let resp = cors_tagged(&["https://a.example"], "OPTIONS", origin, &[]).await;
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::NO_CONTENT,
                "{origin:?}"
            );
            assert_eq!(single_header(&resp, "vary"), Some("Origin"), "{origin:?}");
            assert_eq!(
                resp.headers()
                    .get_all("access-control-allow-origin")
                    .iter()
                    .count(),
                usize::from(granted.is_some()),
                "{origin:?}"
            );
            assert_eq!(
                single_header(&resp, "access-control-allow-origin"),
                granted,
                "{origin:?}"
            );
        }
    }

    /// Under an allowlist, a handler's `Access-Control-Allow-Origin` in any
    /// case never reaches a refused or origin-less request.
    #[tokio::test]
    async fn cors_refused_origin_strips_a_handler_allow_origin_in_any_case() {
        for name in [
            "Access-Control-Allow-Origin",
            "ACCESS-CONTROL-ALLOW-ORIGIN",
            "access-control-allow-origin",
        ] {
            for origin in [Some("https://evil.example"), None] {
                let resp = cors_tagged(
                    &["https://a.example"],
                    "GET",
                    origin,
                    &[(name, "https://evil.example")],
                )
                .await;
                assert_eq!(
                    resp.status(),
                    axum::http::StatusCode::OK,
                    "{name} / {origin:?}"
                );
                assert!(
                    resp.headers().get("access-control-allow-origin").is_none(),
                    "{name} / {origin:?}"
                );
                assert_eq!(
                    single_header(&resp, "vary"),
                    Some("Origin"),
                    "{name} / {origin:?}"
                );
            }
        }
    }

    /// An inner middleware's refusal is tagged like any handler response: it
    /// varies on `Origin`, and grants only an allowed origin.
    #[tokio::test]
    async fn cors_inner_refusal_is_tagged_like_any_response() {
        let h = middleware_with_cors::<String, _>(
            vec!["https://a.example".to_owned()],
            middleware_with_basic_auth::<String, _>(
                "u".to_owned(),
                "p".to_owned(),
                |_req: ServerRequest| {
                    Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                        as IpeTask<String, ServerResponse>
                },
            ),
        );
        for (origin, granted) in [
            ("https://evil.example", None),
            ("https://a.example", Some("https://a.example")),
        ] {
            let resp = cors_sent(&h, "GET", Some(origin)).await;
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{origin}"
            );
            assert_eq!(single_header(&resp, "vary"), Some("Origin"), "{origin}");
            assert_eq!(
                resp.headers()
                    .get_all("access-control-allow-origin")
                    .iter()
                    .count(),
                usize::from(granted.is_some()),
                "{origin}"
            );
            assert_eq!(
                single_header(&resp, "access-control-allow-origin"),
                granted,
                "{origin}"
            );
        }
    }

    /// A list containing `*` grants every origin and never adds `Vary`: no
    /// response depends on `Origin`.
    #[tokio::test]
    async fn cors_wildcard_policy_never_adds_vary() {
        for origins in [&["*"][..], &["https://a.example", "*"][..]] {
            for method in ["GET", "OPTIONS"] {
                for origin in [
                    Some("https://a.example"),
                    Some("https://evil.example"),
                    None,
                ] {
                    let resp = cors_tagged(origins, method, origin, &[]).await;
                    assert_eq!(
                        single_header(&resp, "access-control-allow-origin"),
                        Some("*"),
                        "{origins:?} / {method} / {origin:?}"
                    );
                    assert!(
                        resp.headers().get("vary").is_none(),
                        "{origins:?} / {method} / {origin:?}"
                    );
                }
            }
        }
    }

    /// A handler's `Vary: *` already varies on every header, so it is kept as
    /// is for an allowed and a refused origin alike.
    #[tokio::test]
    async fn cors_vary_star_is_kept() {
        for origin in [Some("https://a.example"), Some("https://evil.example")] {
            let resp = cors_tagged(&["https://a.example"], "GET", origin, &[("Vary", "*")]).await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{origin:?}");
            assert_eq!(single_header(&resp, "vary"), Some("*"), "{origin:?}");
        }
    }

    /// More handler header names than a header map holds is a typed refusal,
    /// never a capacity panic.
    #[test]
    fn head_refuses_more_header_names_than_a_header_map_holds() {
        let mut r = server_text("ok".to_owned());
        for i in 0..=(1_usize << 15) {
            r.headers.insert(format!("x-h{i}"), "v".to_owned());
        }
        for delivery in [ServerDelivery::Buffered, ServerDelivery::Streamed] {
            assert!(
                matches!(
                    assemble_response_head(&r, delivery, framed_security()),
                    Err(response_head::HeadRefusal::Oversize)
                ),
                "{delivery:?}"
            );
        }
    }

    /// A content type that is not a visible-ASCII header value answers 500 on
    /// a buffered and a streamed response alike, as the same handler header.
    #[tokio::test]
    async fn heads_refuse_a_non_ascii_content_type() {
        let mut buffered = server_text("ok".to_owned());
        buffered.contentType = "text/\u{e9}".to_owned();
        for delivery in [ServerDelivery::Buffered, ServerDelivery::Streamed] {
            assert!(
                matches!(
                    assemble_response_head(&buffered, delivery, framed_security()),
                    Err(response_head::HeadRefusal::ContentType)
                ),
                "{delivery:?}"
            );
        }
        let resp = to_axum_response_with(buffered, RequestStreams::new(), framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let (r, streams) = streamed("text/\u{e9}").await;
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .is_none()
        );
    }

    /// A refused head never runs the stream handler; an assembled head does.
    #[tokio::test]
    async fn refused_head_never_runs_the_stream_handler() {
        let stream_with_flag = |ran: std::sync::Arc<std::sync::atomic::AtomicBool>| {
            server_stream_stream::<IpeError, _>("text/event-stream".to_owned(), move |_w| {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
            })
        };
        let built = |result: IpeResult<IpeError, ServerResponse>| {
            let built = match result {
                IpeResult::Ok(r) => Some(r),
                IpeResult::Err(_) => None,
            };
            built.expect("`stream` must build a response")
        };
        let refused_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (result, streams) =
            crate::server_stream::in_stream_scope(stream_with_flag(refused_ran.clone())).await;
        let r = built(result);
        let resp = to_axum_response_with(
            r,
            streams,
            Err(crate::telemetry::FrameAncestorsRefusal::Blank),
        );
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(!refused_ran.load(std::sync::atomic::Ordering::SeqCst));
        let served_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (result, streams) =
            crate::server_stream::in_stream_scope(stream_with_flag(served_ran.clone())).await;
        let r = built(result);
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        for _ in 0..1024 {
            if served_ran.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(served_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A stream sentinel served a second time, by a request that never minted
    /// it, names no handler: it answers 500, never a buffered body that sends
    /// the ticket.
    #[tokio::test]
    async fn abandoned_stream_sentinel_answers_500_without_the_sentinel() {
        let (r, streams) = streamed("text/event-stream").await;
        let again = r.clone();
        let first = to_axum_response_with(r, streams, framed_security());
        assert_eq!(first.status(), axum::http::StatusCode::OK);
        let second = to_axum_response_with(again, RequestStreams::new(), framed_security());
        assert_eq!(
            second.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = axum_body_string(second).await;
        assert!(!body.contains("__ipe_stream:"), "{body:?}");
    }

    /// A request serving another request's exact sentinel answers 500, sends
    /// no sentinel and never runs that handler; the minting request serves it.
    #[tokio::test]
    async fn a_sentinel_from_another_request_never_runs_its_handler() {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (minted, streams) = flagged(&ran).await;
        let foreign =
            to_axum_response_with(minted.clone(), RequestStreams::new(), framed_security());
        assert_eq!(
            foreign.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = axum_body_string(foreign).await;
        assert!(!body.contains("__ipe_stream:"), "{body:?}");
        assert!(
            !ran_eventually(&ran).await,
            "a foreign claim runs no handler"
        );
        let own = to_axum_response_with(minted, streams, framed_security());
        assert_eq!(own.status(), axum::http::StatusCode::OK);
        assert!(ran_eventually(&ran).await, "the minting request runs it");
    }

    /// A live sentinel wrapped in other text answers 500 without the ticket
    /// and never runs its handler; the exact sentinel streams.
    #[tokio::test]
    async fn a_wrapped_live_sentinel_answers_500_and_sends_no_ticket() {
        let wraps: [fn(&str) -> String; 3] = [
            |s| format!("x{s}"),
            |s| format!("{s}x"),
            |s| format!("<p>{s}</p>"),
        ];
        for wrap in wraps {
            let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let (mut r, streams) = flagged(&ran).await;
            let ticket = r
                .body
                .strip_prefix("__ipe_stream:")
                .map(str::to_owned)
                .unwrap_or_default();
            assert_eq!(ticket.len(), 32, "{:?}", r.body);
            r.body = wrap(&r.body);
            let wrapped = r.body.clone();
            let resp = to_axum_response_with(r, streams, framed_security());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{wrapped:?}"
            );
            let body = axum_body_string(resp).await;
            assert!(!body.contains(&ticket), "{wrapped:?}: {body:?}");
            assert!(!ran_eventually(&ran).await, "{wrapped:?}");
        }
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (r, streams) = flagged(&ran).await;
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert!(ran_eventually(&ran).await);
    }

    /// A handler the response never claims drops with its request's table,
    /// releasing what it captured.
    #[tokio::test]
    async fn an_unclaimed_handler_drops_with_its_request() {
        let held = Arc::new(());
        let captured = Arc::clone(&held);
        let task = server_stream_stream::<IpeError, _>("text/plain".to_owned(), move |_w| {
            let _keep = Arc::clone(&captured);
            Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
        });
        let (registered, streams) = crate::server_stream::in_stream_scope(task).await;
        assert!(matches!(registered, IpeResult::Ok(_)));
        drop(registered);
        assert_eq!(Arc::strong_count(&held), 2, "the pending handler holds it");
        let resp = to_axum_response_with(
            server_text("replaced".to_owned()),
            streams,
            framed_security(),
        );
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert_eq!(Arc::strong_count(&held), 1, "the unclaimed handler dropped");
    }

    /// A `stream` registered by a `Task.parallel` branch belongs to the
    /// request the branch runs for, whose response claims it.
    #[tokio::test]
    async fn stream_in_a_spawned_subtask_registers_in_its_request() {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let parallel = crate::task::task_parallel(vec![flagged_stream(Arc::clone(&ran))]);
        let (result, streams) = crate::server_stream::in_stream_scope(parallel).await;
        let built = match result {
            IpeResult::Ok(mut responses) => responses.pop(),
            IpeResult::Err(_) => None,
        };
        assert!(built.is_some(), "the branch registers inside its request");
        let Some(r) = built else {
            return;
        };
        let resp = to_axum_response_with(r, streams, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        assert!(ran_eventually(&ran).await);
    }

    /// `redirect` percent-encodes CTLs, space, non-ASCII and the characters
    /// RFC 3986 neither reserves nor leaves unreserved; reserved characters
    /// and existing `%XX` escapes are kept.
    #[tokio::test]
    async fn redirect_location_is_percent_encoded() {
        for (raw, location) in [
            ("/a b/caf\u{e9}?q=1&r=[x]#f", "/a%20b/caf%C3%A9?q=1&r=[x]#f"),
            ("/%41", "/%41"),
            ("/a\r\nSet-Cookie: x=y", "/a%0D%0ASet-Cookie:%20x=y"),
            (
                "https://e.example/p?x=\"<{|}>\"",
                "https://e.example/p?x=%22%3C%7B%7C%7D%3E%22",
            ),
            ("/\u{65e5}", "/%E6%97%A5"),
        ] {
            let resp = to_axum_response(server_redirect(raw.to_owned()), RequestStreams::new());
            assert_eq!(resp.status(), axum::http::StatusCode::FOUND, "{raw:?}");
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::LOCATION)
                    .and_then(|v| v.to_str().ok()),
                Some(location),
                "{raw:?}"
            );
        }
    }

    /// A parsed non-empty cookie name for a test.
    #[cfg(feature = "jwt")]
    fn sid(raw: &str) -> CookieName {
        CookieName::parse(raw).unwrap()
    }

    /// `Server.cookieToken ""` is an `InvalidInput` error: no cookie source
    /// names a cookie no request can carry.
    #[cfg(feature = "jwt")]
    #[test]
    fn cookie_token_empty_name_is_refused() {
        assert!(matches!(
            server_cookie_token(String::new()),
            IpeResult::Err(IpeError::Error(IpeErrorKind::InvalidInput, ref info))
                if info.message.starts_with("Server.cookieToken:")
        ));
        assert!(matches!(
            server_cookie_token("my sid".to_owned()),
            IpeResult::Ok(TokenSource::Cookie(ref name)) if name.as_str() == "my%20sid"
        ));
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn reissue_set_cookie_encodes_name_and_token() {
        let line = reissue_set_cookie(&sid("my sid"), "t;ok", 1800, false);
        assert!(
            line.starts_with("my%20sid=t%3Bok; Path=/; HttpOnly; SameSite="),
            "{line}"
        );
        assert!(
            axum::http::HeaderValue::from_str(line.as_str()).is_ok(),
            "{line}"
        );
    }

    fn mk_req(
        method: &str,
        cookies: HashMap<String, String>,
        headers: HashMap<String, String>,
    ) -> ServerRequest {
        ServerRequest {
            method: method.to_string(),
            path: "/".to_string(),
            body: String::new(),
            headers,
            params: HashMap::new(),
            query: HashMap::new(),
            cookies,
            remoteAddr: String::new(),
        }
    }

    #[tokio::test]
    async fn csrf_get_mints_and_sets_cookie_no_check() {
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("GET", HashMap::new(), HashMap::new());
        let resp = h(req).await;
        match resp {
            IpeResult::Ok(r) => assert_eq!(r.cookies.len(), 1, "GET must mint a fresh cookie"),
            IpeResult::Err(_) => panic!("GET must never be rejected"),
        }
    }

    /// A CSRF mint is drawn only for a safe request with no well-formed
    /// cookie, and a refused mint answers 503 without reaching the handler.
    #[tokio::test]
    async fn csrf_mint_failure_is_503() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let mints = Arc::new(AtomicUsize::new(0));
        let handler_calls = Arc::clone(&calls);
        let mint_calls = Arc::clone(&mints);
        let h = middleware_with_csrf_minting::<String, _, _>(
            move |_req: ServerRequest| {
                handler_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                    as IpeTask<String, ServerResponse>
            },
            move || {
                mint_calls.fetch_add(1, Ordering::SeqCst);
                Err(EntropyError)
            },
        );
        let got = h(mk_req("GET", HashMap::new(), HashMap::new())).await;
        assert!(matches!(&got, IpeResult::Ok(r) if r.status == 503));
        let IpeResult::Ok(resp) = got else { return };
        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("retry-after") && v == "1"),
            "a refused mint asks the client to retry"
        );
        assert!(resp.cookies.is_empty(), "a refused mint sets no cookie");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "the handler never runs");
        assert_eq!(mints.load(Ordering::SeqCst), 1);

        let got = h(mk_req("POST", HashMap::new(), HashMap::new())).await;
        assert!(matches!(&got, IpeResult::Ok(r) if r.status == 403));
        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "an unsafe method never mints"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let mut cookies = HashMap::new();
        cookies.insert(csrf_cookie_name().text().to_owned(), "e".repeat(64));
        let got = h(mk_req("GET", cookies, HashMap::new())).await;
        assert!(matches!(&got, IpeResult::Ok(r) if r.status == 200));
        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "a well-formed cookie is reused"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A minted CSRF token is the 64 lowercase-hex rendering of its 32 drawn
    /// bytes, and a refused draw yields no token.
    #[test]
    fn csrf_token_renders_its_draw_and_refuses_without_entropy() {
        let tok = mint_csrf_token_with(|buf| {
            buf.fill(0xa5);
            Ok(())
        });
        assert_eq!(tok, Ok("a5".repeat(32)));
        assert!(tok.as_deref().is_ok_and(csrf_token_well_formed));
        assert_eq!(
            mint_csrf_token_with(|_| Err(EntropyError)),
            Err(EntropyError)
        );
    }

    #[tokio::test]
    async fn csrf_post_without_header_rejected() {
        let mut cookies = HashMap::new();
        cookies.insert(csrf_cookie_name().text().to_owned(), "a".repeat(64));
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("POST", cookies, HashMap::new());
        match h(req).await {
            IpeResult::Ok(r) => assert_eq!(r.status, 403),
            IpeResult::Err(_) => panic!("expected an Ok(403), not an Err"),
        }
    }

    #[tokio::test]
    async fn csrf_post_with_matching_cookie_and_header_allowed() {
        let tok = "b".repeat(64);
        let mut cookies = HashMap::new();
        cookies.insert(csrf_cookie_name().text().to_owned(), tok.clone());
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".to_string(), tok);
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("POST", cookies, headers);
        match h(req).await {
            IpeResult::Ok(r) => assert_eq!(r.status, 200),
            IpeResult::Err(_) => panic!("expected Ok(200)"),
        }
    }

    #[tokio::test]
    async fn csrf_post_with_mismatched_cookie_and_header_rejected() {
        let mut cookies = HashMap::new();
        cookies.insert(csrf_cookie_name().text().to_owned(), "c".repeat(64));
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".to_string(), "d".repeat(64));
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("POST", cookies, headers);
        match h(req).await {
            IpeResult::Ok(r) => assert_eq!(r.status, 403),
            IpeResult::Err(_) => panic!("expected Ok(403)"),
        }
    }

    /// Regression for the well-formedness gap: an EQUAL pair of malformed
    /// values (too short to be a real server-minted token) must still be
    /// rejected — the compare alone (`cookie_tok == header_tok`) is not
    /// sufficient, both sides must also look like a genuine token.
    #[tokio::test]
    async fn csrf_post_with_matching_but_malformed_tokens_rejected() {
        let mut cookies = HashMap::new();
        cookies.insert(csrf_cookie_name().text().to_owned(), "x".to_string());
        let mut headers = HashMap::new();
        headers.insert("x-csrf-token".to_string(), "x".to_string());
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("POST", cookies, headers);
        match h(req).await {
            IpeResult::Ok(r) => assert_eq!(r.status, 403),
            IpeResult::Err(_) => panic!("expected Ok(403)"),
        }
    }

    // ── CSRF cookie `Secure` — ENV-vs-TLS combined gate ──────────────

    #[test]
    fn request_is_https_ignored_without_trust_opt_in() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-proto".to_string(), "https".to_string());
        assert!(
            !request_is_https_with_trust(&headers, false),
            "must ignore X-Forwarded-Proto without IPE_TRUSTED_PROXY opt-in"
        );
    }

    #[test]
    fn request_is_https_honoured_when_trusted() {
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-proto".to_string(), "https".to_string());
        assert!(request_is_https_with_trust(&headers, true));

        let mut headers2 = HashMap::new();
        headers2.insert("x-forwarded-proto".to_string(), "http".to_string());
        assert!(!request_is_https_with_trust(&headers2, true));
    }

    #[test]
    fn request_is_https_missing_header_is_not_https() {
        let headers = HashMap::new();
        assert!(!request_is_https_with_trust(&headers, true));
    }

    /// `csrf_set_cookie_value`'s combined gate: `Secure` when EITHER there is
    /// no dev intent OR the (pre-captured) request-scoped TLS signal is true.
    /// Exercises all four (dev intent, `request_is_https`) combinations and
    /// the cookie name — the pure-function core, independent of env mutation.
    #[test]
    fn csrf_cookie_secure_or_gate_truth_table() {
        let tok = "a".repeat(64);
        let dev = crate::telemetry::test_dev_intent();
        // (a) dev intent, request IS https -> Secure.
        assert!(
            csrf_set_cookie_value_with(&tok, true, Some(&dev)).contains("; Secure"),
            "TLS-detected request must get Secure regardless of posture"
        );
        // (b) dev intent, request NOT https -> no Secure (dev-mode-correct).
        let plain = csrf_set_cookie_value_with(&tok, false, Some(&dev));
        assert!(!plain.contains("; Secure"), "{plain}");
        assert!(plain.starts_with("ipe_csrf="), "{plain}");
        // (c)/(d) no dev intent -> Secure and `__Host-`, TLS or not.
        for https in [false, true] {
            let cookie = csrf_set_cookie_value_with(&tok, https, None);
            assert!(cookie.contains("; Secure"), "{cookie}");
            assert!(cookie.starts_with("__Host-ipe_csrf="), "{cookie}");
        }
        assert!(cookie_secure_floor_with(None));
        assert!(!cookie_secure_floor_with(Some(&dev)));
    }

    // A release binary under `ENV=dev` keeps every `Ipe.Http.Server` cookie
    // `Secure`, and the CSRF cookie `__Host-`-prefixed.
    #[cfg(not(feature = "dev-posture"))]
    #[test]
    fn cookies_secure_on_release_under_env_dev() {
        crate::system::locked_set_var("ENV", "dev");
        crate::system::locked_set_var("IPE_ENV", "dev");
        let tok = "e".repeat(64);
        let csrf = csrf_set_cookie_value(&tok, false);
        let name = csrf_cookie_name();
        let resp = server_with_cookie(cookie("sid", "v"), server_text("ok".into()));
        #[cfg(feature = "web")]
        let web_secure = crate::web::csrf::cookies_secure();
        #[cfg(not(feature = "web"))]
        let web_secure = true;
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
        assert!(csrf.contains("; Secure"), "{csrf}");
        assert_eq!(name.as_str(), "__Host-ipe_csrf");
        assert!(
            resp.cookies.iter().all(|c| c.contains("; Secure")),
            "{:?}",
            resp.cookies
        );
        assert!(web_secure);
    }

    #[test]
    fn csrf_cookie_secure_production_forces_secure_even_without_tls_signal() {
        // (c) the exact gap this closes: ENV=production set, but THIS
        // request is not detected as TLS (e.g. IPE_TRUSTED_PROXY unset, or
        // no proxy in front) -> Secure still fires off the unconditional
        // production floor. Matches the session cookie's own combined-gate
        // semantics in live/mod.rs::page_response (`csrf::cookies_secure()
        // || request_is_https(headers)` — production forces Secure
        // unconditionally; the request-scoped signal only ADDS Secure in
        // the non-production case).
        crate::system::locked_set_var("ENV", "production");
        let tok = "b".repeat(64);
        let cookie = csrf_set_cookie_value(&tok, false);
        crate::system::locked_remove_var("ENV");
        assert!(
            cookie.contains("; Secure"),
            "ENV=production must force Secure even when this request isn't TLS-detected: {cookie}"
        );
    }

    #[test]
    fn csrf_cookie_secure_production_and_tls_signal_both_true() {
        crate::system::locked_set_var("ENV", "production");
        let tok = "c".repeat(64);
        let cookie = csrf_set_cookie_value(&tok, true);
        crate::system::locked_remove_var("ENV");
        assert!(cookie.contains("; Secure"));
    }

    /// End-to-end through `middleware_with_csrf` (not just the pure
    /// `csrf_set_cookie_value` helper): a GET request carrying
    /// `X-Forwarded-Proto: https` on a dev build mints a non-Secure cookie
    /// unless `IPE_TRUSTED_PROXY` is honoured, proving the signal survives the
    /// capture-before-move + thread-through-the-closure adaptation.
    #[cfg(feature = "dev-posture")]
    #[tokio::test]
    async fn dev_posture_pin_csrf_middleware_ignores_untrusted_forwarded_proto() {
        // Dev build, nothing set, so `Secure` can only come from the forwarded scheme.
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
        let mut headers = HashMap::new();
        headers.insert("x-forwarded-proto".to_string(), "https".to_string());
        let h = middleware_with_csrf::<String, _>(|_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".into()))))
                as IpeTask<String, ServerResponse>
        });
        let req = mk_req("GET", HashMap::new(), headers);
        // `middleware_with_csrf` calls the process-wide `request_is_https`
        // (via `trust_proxy_headers()`'s `OnceLock`), which without
        // `IPE_TRUSTED_PROXY` set never trusts the header — so this test
        // documents the untrusted-by-default floor: no Secure without the
        // operator's opt-in, even though the header claims https.
        let result = h(req).await;
        let IpeResult::Ok(r) = result else {
            assert!(
                matches!(result, IpeResult::Ok(_)),
                "GET must never be rejected"
            );
            return;
        };
        assert_eq!(r.cookies.len(), 1);
        assert!(
            r.cookies.iter().all(|c| !c.contains("; Secure")),
            "X-Forwarded-Proto must be ignored without IPE_TRUSTED_PROXY opt-in: {:?}",
            r.cookies
        );
    }

    /// `Server.listen` on a free loopback port with one `GET /` route, spawned.
    fn spawn_listen() -> Option<(u16, tokio::task::JoinHandle<IpeResult<String, ()>>)> {
        let port = free_loopback_port()?;
        crate::system::locked_set_var("IPE_HTTP_BIND", "127.0.0.1");
        crate::system::locked_remove_var(crate::env_registry::listen::SERVER_PORT.name());
        crate::system::locked_remove_var(crate::LISTEN_PORT_RELOCATION_ENV);
        let route = server_get::<String, _>("/".to_owned(), |_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".to_owned()))))
                as IpeTask<String, ServerResponse>
        });
        let task = tokio::spawn(server_listen(i64::from(port), vec![route]));
        Some((port, task))
    }

    /// A `GET path` request carrying `host` verbatim as its `Host` header.
    fn get_with_host(path: &str, host: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    /// A rebound name reaches no route of a real `Server.listen`: `GET /` and
    /// an unknown path both answer 421 with no cookie, before routing; the same
    /// listener addressed by its IP literal serves the route.
    #[tokio::test]
    async fn dev_posture_pin_listen_refuses_a_rebound_host() {
        let (port, task) = spawn_listen().unwrap();
        let evil = format!("evil.example:{port}");
        for path in ["/", "/no/such/route"] {
            let resp = raw_exchange(port, &get_with_host(path, &evil))
                .await
                .unwrap();
            assert_eq!(raw_status(&resp), 421, "{path}: {resp}");
            assert!(resp.contains("host_not_admitted"), "{path}: {resp}");
            assert!(
                !resp.to_ascii_lowercase().contains("set-cookie"),
                "{path}: {resp}"
            );
        }
        let ip = format!("127.0.0.1:{port}");
        let resp = raw_exchange(port, &get_with_host("/", &ip)).await.unwrap();
        assert_eq!(raw_status(&resp), 200, "{resp}");
        task.abort();
        crate::system::locked_remove_var("IPE_HTTP_BIND");
    }

    /// A real `Server.listen` admits a name `IPE_HTTP_ALLOWED_HOSTS` declares,
    /// and still refuses a name below it with 421.
    #[tokio::test]
    async fn dev_posture_pin_declared_name_admits_on_listen() {
        crate::system::locked_set_var("IPE_HTTP_ALLOWED_HOSTS", "review.example.com");
        let (port, task) = spawn_listen().unwrap();
        let declared = format!("review.example.com:{port}");
        let resp = raw_exchange(port, &get_with_host("/", &declared))
            .await
            .unwrap();
        assert_eq!(raw_status(&resp), 200, "{resp}");
        let below = format!("x.review.example.com:{port}");
        let resp = raw_exchange(port, &get_with_host("/", &below))
            .await
            .unwrap();
        assert_eq!(raw_status(&resp), 421, "{resp}");
        assert!(resp.contains("host_not_admitted"), "{resp}");
        task.abort();
        crate::system::locked_remove_var("IPE_HTTP_ALLOWED_HOSTS");
        crate::system::locked_remove_var("IPE_HTTP_BIND");
    }

    /// A malformed `IPE_HTTP_ALLOWED_HOSTS` refuses `Server.listen` before its
    /// socket opens, naming the variable and never the value. The port is
    /// held, so a bind attempted first would answer its own address-in-use
    /// refusal instead of the host list's.
    #[tokio::test]
    async fn listen_refuses_a_malformed_allowed_hosts_before_binding() {
        let held = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        crate::system::locked_set_var("IPE_HTTP_ALLOWED_HOSTS", "hidden.example:80");
        crate::system::locked_set_var("IPE_HTTP_BIND", "127.0.0.1");
        crate::system::locked_remove_var(crate::env_registry::listen::SERVER_PORT.name());
        crate::system::locked_remove_var(crate::LISTEN_PORT_RELOCATION_ENV);
        let route = server_get::<String, _>("/".to_owned(), |_req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text("ok".to_owned()))))
                as IpeTask<String, ServerResponse>
        });
        let outcome = server_listen::<String>(i64::from(port), vec![route]).await;
        drop(held);
        crate::system::locked_remove_var("IPE_HTTP_ALLOWED_HOSTS");
        crate::system::locked_remove_var("IPE_HTTP_BIND");
        assert!(matches!(outcome, IpeResult::Err(_)), "{outcome:?}");
        let IpeResult::Err(message) = outcome else {
            return;
        };
        assert!(message.contains("IPE_HTTP_ALLOWED_HOSTS"), "{message}");
        assert!(!message.contains("hidden"), "{message}");
    }

    /// A real `Server.listen` refuses a malformed URL with 400 whether or not
    /// a route would match it, and routes another spelling of `/api` to
    /// `/api`, its handler reading the canonical path.
    #[tokio::test]
    async fn listen_refuses_a_malformed_url_and_routes_its_canonical_spelling() {
        let port = free_loopback_port().unwrap();
        crate::system::locked_set_var("IPE_HTTP_BIND", "127.0.0.1");
        crate::system::locked_remove_var(crate::env_registry::listen::SERVER_PORT.name());
        crate::system::locked_remove_var(crate::LISTEN_PORT_RELOCATION_ENV);
        let route = server_get::<String, _>("/api".to_owned(), |req: ServerRequest| {
            Box::pin(ready(ok_res::<String, _>(server_text(format!(
                "api {}",
                req.path
            ))))) as IpeTask<String, ServerResponse>
        });
        let task: tokio::task::JoinHandle<IpeResult<String, ()>> =
            tokio::spawn(server_listen(i64::from(port), vec![route]));
        let ip = format!("127.0.0.1:{port}");
        for path in [
            "/%zz",
            "/%",
            "/api/%zz",
            "/no/such/route/%C0%AF",
            "/api?q=%zz",
        ] {
            let resp = raw_exchange(port, &get_with_host(path, &ip)).await.unwrap();
            assert_eq!(raw_status(&resp), 400, "{path}: {resp}");
            assert!(!resp.contains("%zz"), "{path} must not echo the request");
        }
        for path in ["/api", "/%61pi", "/%61%70%69", "//api"] {
            let resp = raw_exchange(port, &get_with_host(path, &ip)).await.unwrap();
            assert_eq!(raw_status(&resp), 200, "{path}: {resp}");
            assert!(resp.ends_with("api /api"), "{path}: {resp}");
        }
        task.abort();
        crate::system::locked_remove_var("IPE_HTTP_BIND");
    }

    /// An authority carrying userinfo is malformed and refused with 421 in
    /// every build posture, though its host is the loopback literal.
    #[tokio::test]
    async fn malformed_authority_refuses_in_every_posture() {
        let (port, task) = spawn_listen().unwrap();
        let resp = raw_exchange(port, &get_with_host("/", "user@127.0.0.1"))
            .await
            .unwrap();
        assert_eq!(raw_status(&resp), 421, "{resp}");
        assert!(resp.contains("host_not_admitted"), "{resp}");
        task.abort();
        crate::system::locked_remove_var("IPE_HTTP_BIND");
    }

    /// A socket whose peer never takes a frame.
    struct StalledSocket;

    impl futures_util::Stream for StalledSocket {
        type Item = Result<axum::extract::ws::Message, axum::Error>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    impl futures_util::Sink<axum::extract::ws::Message> for StalledSocket {
        type Error = std::convert::Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn start_send(
            self: Pin<&mut Self>,
            _item: axum::extract::ws::Message,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Pending
        }
    }

    /// Whether `ws_loop` over a [`StalledSocket`] ends within twice the
    /// close deadline, under `max_connections` and `drain`.
    async fn stalled_loop_ends(max_connections: usize, drain: shutdown::Drain) -> bool {
        let ceilings = WsCeilings {
            send_buffer: 16,
            max_connections,
            heartbeat_secs: 30,
        };
        let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let served = ws_loop(
            StalledSocket,
            ws_server_default_cfg::<String>(),
            id,
            ceilings,
            ChannelCredentials::of_request(),
            None,
            drain,
        );
        tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE * 2, served)
            .await
            .is_ok()
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_the_full_drain_refuses_ends_within_its_close_deadline() {
        assert!(
            stalled_loop_ends(usize::MAX, shutdown::tests::full_drain()).await,
            "an uncounted socket's close frame never outlives its deadline"
        );
    }

    /// A socket callback still running when the shutdown closes is cancelled,
    /// and no callback starts after it.
    #[tokio::test(start_paused = true)]
    async fn a_socket_callback_running_past_the_grace_is_cancelled_by_the_close() {
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            std::sync::Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (entering, closing) = (
            std::sync::Arc::clone(&entered),
            std::sync::Arc::clone(&closed),
        );
        let cfg = WsServerCfg {
            onConnect: std::sync::Arc::new(move |_: WsHandle| {
                let entering = std::sync::Arc::clone(&entering);
                Box::pin(async move {
                    entering.notify_one();
                    std::future::pending::<()>().await;
                    ok_res(())
                }) as IpeTask<String, ()>
            }),
            onClose: std::sync::Arc::new(move |_: WsHandle| {
                let closing = std::sync::Arc::clone(&closing);
                Box::pin(async move {
                    closing.store(true, Ordering::SeqCst);
                    ok_res(())
                }) as IpeTask<String, ()>
            }),
            ..ws_server_default_cfg::<String>()
        };
        let ceilings = WsCeilings {
            send_buffer: 16,
            max_connections: usize::MAX,
            heartbeat_secs: 30,
        };
        let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let served = tokio::spawn(ws_loop(
            StalledSocket,
            cfg,
            id,
            ceilings,
            ChannelCredentials::of_request(),
            None,
            armed.drain(),
        ));
        let began = tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE, entered.notified()).await;
        assert!(began.is_ok(), "the socket's onConnect runs");
        let started = tokio::time::Instant::now();
        let _settled = armed.cancel_work().await;
        assert!(
            started.elapsed() < shutdown::WORK_CANCEL_DEADLINE,
            "the cancelled callback releases its unit before the cancel deadline"
        );
        let ended = tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE * 2, served).await;
        assert!(
            matches!(ended, Ok(Ok(()))),
            "the close cancels the running callback and ends the socket"
        );
        assert!(
            !closed.load(Ordering::SeqCst),
            "no callback starts once the shutdown closes"
        );
    }

    /// A socket whose peer sends nothing and takes every frame, recording it.
    struct RecordingSocket(Arc<std::sync::Mutex<Vec<axum::extract::ws::Message>>>);

    impl futures_util::Stream for RecordingSocket {
        type Item = Result<axum::extract::ws::Message, axum::Error>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    impl futures_util::Sink<axum::extract::ws::Message> for RecordingSocket {
        type Error = std::convert::Infallible;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn start_send(
            self: Pin<&mut Self>,
            item: axum::extract::ws::Message,
        ) -> Result<(), Self::Error> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// A socket callback that sets `flag` when it runs and returns at once.
    fn flagging(
        flag: &Arc<std::sync::atomic::AtomicBool>,
    ) -> Arc<dyn Fn(WsHandle) -> IpeTask<String, ()> + Send + Sync> {
        let flag = Arc::clone(flag);
        Arc::new(move |_: WsHandle| {
            let flag = Arc::clone(&flag);
            Box::pin(async move {
                flag.store(true, Ordering::SeqCst);
                ok_res(())
            }) as IpeTask<String, ()>
        })
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_past_the_work_ceiling_closes_going_away_before_its_on_connect() {
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        armed.force_work_state(shutdown::WORK_CEILING);
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = WsServerCfg {
            onConnect: flagging(&connected),
            ..ws_server_default_cfg::<String>()
        };
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ceilings = WsCeilings {
            send_buffer: 16,
            max_connections: usize::MAX,
            heartbeat_secs: 30,
        };
        let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let served = ws_loop(
            RecordingSocket(Arc::clone(&sent)),
            cfg,
            id,
            ceilings,
            ChannelCredentials::of_request(),
            None,
            armed.drain(),
        );
        let ended = tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE * 2, served).await;
        assert!(ended.is_ok(), "a refused socket ends at once");
        assert!(
            !connected.load(Ordering::SeqCst),
            "a socket past the ceiling never runs onConnect"
        );
        let frames = sent.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let away = matches!(
            frames.as_slice(),
            [axum::extract::ws::Message::Close(Some(frame))]
                if frame.code == axum::extract::ws::close_code::AWAY
        );
        assert!(away, "the one frame is a 1001 close; sent {frames:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_the_close_ends_skips_its_on_close() {
        let (armed, _signals) = shutdown::tests::armed_with(
            shutdown::ShutdownPlan::bare("test"),
            std::time::Duration::ZERO,
            Arc::new(std::sync::atomic::AtomicI32::new(0)),
        );
        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cfg = WsServerCfg {
            onConnect: flagging(&connected),
            onClose: flagging(&closed),
            ..ws_server_default_cfg::<String>()
        };
        let ceilings = WsCeilings {
            send_buffer: 16,
            max_connections: usize::MAX,
            heartbeat_secs: 30,
        };
        let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let served = tokio::spawn(ws_loop(
            RecordingSocket(Arc::new(std::sync::Mutex::new(Vec::new()))),
            cfg,
            id,
            ceilings,
            ChannelCredentials::of_request(),
            None,
            armed.drain(),
        ));
        let opened = tokio::time::Instant::now() + shutdown::WS_CLOSE_DEADLINE;
        while !connected.load(Ordering::SeqCst) {
            assert!(
                tokio::time::Instant::now() < opened,
                "the socket's onConnect runs"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let _settled = armed.cancel_work().await;
        let ended = tokio::time::timeout(shutdown::WS_CLOSE_DEADLINE * 2, served).await;
        assert!(matches!(ended, Ok(Ok(()))), "the close ends the socket");
        assert!(
            !closed.load(Ordering::SeqCst),
            "a socket the close ends never runs onClose"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_socket_over_the_peer_ceiling_ends_within_its_close_deadline() {
        assert!(
            stalled_loop_ends(0, shutdown::Drain::never()).await,
            "a refused peer's close frame never outlives its deadline"
        );
    }

    // ── authenticated routes (fail-closed) ────────────────────────────
    #[cfg(feature = "jwt")]
    mod authed {
        use super::*;

        const SECRET: &str = "a-test-secret-of-32-bytes-padding";

        fn req_with(headers: &[(&str, &str)], cookies: &[(&str, &str)]) -> ServerRequest {
            ServerRequest {
                method: "GET".to_string(),
                path: "/me".to_string(),
                body: String::new(),
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                params: HashMap::new(),
                query: HashMap::new(),
                cookies: cookies
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
                remoteAddr: String::new(),
            }
        }

        fn hs256(claims: &serde_json::Value) -> String {
            let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
            let key = jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes());
            jsonwebtoken::encode(&header, claims, &key).expect("encode")
        }

        // Drive `server_get_authed`'s guarded handler directly: a handler that
        // answers 200 with the principal's subject, so the response status tells
        // us whether the middleware minted (200) or rejected (401).
        async fn run(cfg: AuthConfig, req: ServerRequest) -> ServerResponse {
            let route = server_get_authed::<String, _>("/me".to_string(), cfg, |_req, p| {
                let subject = crate::principal::principal_subject(p);
                Box::pin(std::future::ready(ok_res(server_text(subject))))
            });
            let RouteTarget::Handler(h) = route.target else {
                panic!("authed route must carry a handler");
            };
            dispatch(&h, req)
                .await
                .0
                .expect("guarded handler never returns Err")
        }

        // ── armed revocation gate ─────────────────────────────────────────

        /// A bearer request carrying `claims`.
        fn bearer_req(claims: &serde_json::Value) -> ServerRequest {
            let token = hs256(claims);
            req_with(&[("authorization", &format!("Bearer {token}"))], &[])
        }

        /// The response of an authed route under `cfg` whose handler answers
        /// how many credentials its request is bound to.
        async fn run_counting_bindings(cfg: AuthConfig, req: ServerRequest) -> ServerResponse {
            let route = server_get_authed::<String, _>("/me".to_string(), cfg, |_req, _p| {
                let bound = request_bindings()
                    .and_then(|bindings| bindings.lock().ok().map(|held| held.len()))
                    .unwrap_or_default();
                Box::pin(std::future::ready(ok_res(server_text(bound.to_string()))))
            });
            let RouteTarget::Handler(h) = route.target else {
                return plain_resp(500, "no handler", &[]);
            };
            dispatch(&h, req)
                .await
                .0
                .expect("guarded handler never returns Err")
        }

        #[tokio::test]
        async fn authed_route_armed_refuses_jti_less_token() {
            let claims = serde_json::json!({ "sub": "s1-subject", "exp": 9_999_999_999i64 });
            let armed = server_with_revocation(1, bearer_cfg());
            assert_eq!(
                run(armed, bearer_req(&claims)).await.status,
                401,
                "an armed route refuses a token it cannot revoke by session"
            );
            assert_eq!(
                run(bearer_cfg(), bearer_req(&claims)).await.status,
                200,
                "an unarmed route admits the same token"
            );
        }

        #[tokio::test]
        async fn authed_route_routes_through_armed_gate() {
            let claims = serde_json::json!({
                "sub": "s2-subject",
                "jti": "s2-jti",
                "exp": 9_999_999_999i64,
            });
            let armed = || server_with_revocation(1, bearer_cfg());
            let admitted = run_counting_bindings(armed(), bearer_req(&claims)).await;
            assert_eq!(admitted.status, 200);
            assert_eq!(
                admitted.body, "1",
                "the admitted credential is bound to the request"
            );
            crate::revocation::revoke_subject("s2-subject".to_string()).expect("revoke");
            assert_eq!(
                run_counting_bindings(armed(), bearer_req(&claims))
                    .await
                    .status,
                401,
                "a revoked subject is refused"
            );
            crate::revocation::restore_subject("s2-subject").expect("restore");
            assert_eq!(
                run_counting_bindings(armed(), bearer_req(&claims))
                    .await
                    .status,
                200,
                "a restored subject is admitted again"
            );
        }

        /// Set on the child process [`server_route_arms_process_mode`] spawns;
        /// its child half is a no-op without it.
        const ARMS_CHILD_MARKER: &str = "IPE_SERVER_ARMS_PROCESS_CHILD";

        /// Printed by the child half once it has observed both modes.
        const ARMS_CHILD_OBSERVED: &str = "server route process arming observed";

        /// Building an armed route arms the process mode; an unarmed one does
        /// not.
        ///
        /// The arming is process-wide and never cleared, so it runs in a child
        /// process: here it would arm every other test of the binary.
        #[test]
        fn server_route_arms_process_mode() {
            let module = module_path!();
            let module = module.split_once("::").map_or(module, |(_, rest)| rest);
            let filter = format!("{module}::server_route_arms_process_mode_child");
            let out = std::env::current_exe().and_then(|exe| {
                std::process::Command::new(exe)
                    .args([
                        "--exact",
                        filter.as_str(),
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(ARMS_CHILD_MARKER, "1")
                    .env_remove("IPE_AUTH_REVOCATION")
                    .stdin(std::process::Stdio::null())
                    .output()
            });
            let observed = out.as_ref().is_ok_and(|out| {
                out.status.success()
                    && std::str::from_utf8(&out.stdout)
                        .is_ok_and(|text| text.contains(ARMS_CHILD_OBSERVED))
            });
            assert!(observed, "the child must observe the arming: {out:?}");
        }

        /// The child half of [`server_route_arms_process_mode`].
        #[test]
        #[ignore = "run as a child process by server_route_arms_process_mode"]
        fn server_route_arms_process_mode_child() {
            use crate::app_config::RevocationMode;
            if crate::system::read_env_var(ARMS_CHILD_MARKER).as_deref() != Ok("1") {
                return;
            }
            let handler = |_req: ServerRequest, _p: crate::principal::Principal| {
                Box::pin(std::future::ready(ok_res::<String, _>(server_text(
                    String::new(),
                )))) as IpeTask<String, ServerResponse>
            };
            assert_eq!(crate::revocation::process_mode(), RevocationMode::Off);
            let _unarmed = server_get_authed("/off".to_string(), bearer_cfg(), handler);
            assert_eq!(
                crate::revocation::process_mode(),
                RevocationMode::Off,
                "an unarmed route leaves the process unarmed"
            );
            let _armed = server_get_authed(
                "/store".to_string(),
                server_with_revocation(1, bearer_cfg()),
                handler,
            );
            assert_eq!(
                crate::revocation::process_mode(),
                RevocationMode::Store,
                "an armed route arms the process"
            );
            println!("\n{ARMS_CHILD_OBSERVED}");
        }

        fn bearer_cfg() -> AuthConfig {
            server_auth_config(
                crate::secret::secret_from_string(SECRET.to_string()),
                TokenSource::BearerHeader,
            )
        }

        #[tokio::test]
        async fn missing_token_is_401() {
            let resp = run(bearer_cfg(), req_with(&[], &[])).await;
            assert_eq!(resp.status, 401, "no Authorization header must fail closed");
        }

        #[tokio::test]
        async fn malformed_token_is_401() {
            let req = req_with(&[("authorization", "Bearer not-a-jwt")], &[]);
            let resp = run(bearer_cfg(), req).await;
            assert_eq!(resp.status, 401, "an unverifiable token must fail closed");
        }

        #[tokio::test]
        async fn expired_token_is_401() {
            let token = hs256(&serde_json::json!({ "sub": "u1", "exp": 1 }));
            let req = req_with(&[("authorization", &format!("Bearer {token}"))], &[]);
            let resp = run(bearer_cfg(), req).await;
            assert_eq!(resp.status, 401, "an expired token must fail closed");
        }

        #[tokio::test]
        async fn absent_subject_claim_is_401() {
            let token = hs256(&serde_json::json!({ "role": "admin", "exp": 9_999_999_999i64 }));
            let req = req_with(&[("authorization", &format!("Bearer {token}"))], &[]);
            let resp = run(bearer_cfg(), req).await;
            assert_eq!(
                resp.status, 401,
                "a token with no subject claim must fail closed"
            );
        }

        #[tokio::test]
        async fn valid_bearer_token_mints_and_dispatches() {
            let token = hs256(&serde_json::json!({ "sub": "user-7", "exp": 9_999_999_999i64 }));
            let req = req_with(&[("authorization", &format!("Bearer {token}"))], &[]);
            let resp = run(bearer_cfg(), req).await;
            assert_eq!(
                resp.status, 200,
                "a valid token must dispatch to the handler"
            );
            assert_eq!(resp.body, "user-7", "the handler sees the minted subject");
        }

        #[tokio::test]
        async fn valid_cookie_token_mints_and_dispatches() {
            let token = hs256(&serde_json::json!({ "sub": "user-9", "exp": 9_999_999_999i64 }));
            let cfg = server_auth_config(
                crate::secret::secret_from_string(SECRET.to_string()),
                TokenSource::Cookie(sid("ipe_sid")),
            );
            let resp = run(cfg, req_with(&[], &[("ipe_sid", &token)])).await;
            assert_eq!(resp.status, 200, "a valid cookie token must dispatch");
            assert_eq!(resp.body, "user-9");
        }

        #[tokio::test]
        async fn wrong_secret_is_401() {
            let token = hs256(&serde_json::json!({ "sub": "u1", "exp": 9_999_999_999i64 }));
            let cfg = server_auth_config(
                crate::secret::secret_from_string("a-DIFFERENT-secret-32-bytes-pad!".to_string()),
                TokenSource::BearerHeader,
            );
            let req = req_with(&[("authorization", &format!("Bearer {token}"))], &[]);
            let resp = run(cfg, req).await;
            assert_eq!(
                resp.status, 401,
                "a token signed under another secret must fail closed"
            );
        }

        // ── sliding re-issue ──────────────────────────────────────────────

        fn now_secs() -> i64 {
            std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("system time is after epoch")
                .as_secs() as i64
        }

        fn cookie_cfg() -> AuthConfig {
            server_auth_config(
                crate::secret::secret_from_string(SECRET.to_string()),
                TokenSource::Cookie(sid("ipe_sid")),
            )
        }

        /// A cookie token past the re-issue threshold (exp - slide_window/2)
        /// triggers a Set-Cookie response header with the refreshed token.
        /// The refreshed cookie carries the same name, Path=/, HttpOnly, and
        /// SameSite=Lax attributes.
        #[tokio::test]
        async fn cookie_past_threshold_gets_reissue_set_cookie() {
            let now = now_secs();
            // exp = now + 800; default slide = 1800s, threshold = exp - 900 = now - 100.
            // now > now - 100, so past_threshold = true; cap is in the future.
            let token = hs256(&serde_json::json!({
                "sub": "user-slide",
                "exp": now + 800,
                "iat": now - 600,
                "cap": now + 7200,
            }));
            let resp = run(cookie_cfg(), req_with(&[], &[("ipe_sid", &token)])).await;
            assert_eq!(
                resp.status, 200,
                "valid token must still dispatch the handler"
            );
            assert!(
                !resp.cookies.is_empty(),
                "a re-issue Set-Cookie must be attached for a past-threshold cookie token"
            );
            let cookie = &resp.cookies[0];
            assert!(
                cookie.starts_with("ipe_sid="),
                "re-issued cookie must carry the same name: {cookie}"
            );
            assert!(
                cookie.contains("; Path=/"),
                "re-issued cookie must include Path=/: {cookie}"
            );
            assert!(
                cookie.contains("; HttpOnly"),
                "re-issued cookie must be HttpOnly: {cookie}"
            );
            assert!(
                cookie.contains("; SameSite="),
                "re-issued cookie must include SameSite: {cookie}"
            );
            assert!(
                cookie.contains("; Max-Age="),
                "re-issued cookie must include Max-Age: {cookie}"
            );
        }

        /// A cookie token whose time claims are written as fractional numbers
        /// slides like an integer one: the throttle reads the `exp` the verifier
        /// judged, never the claim's text.
        #[tokio::test]
        async fn fractional_exp_still_slides() {
            let now = now_secs();
            let claims: serde_json::Value = serde_json::from_str(&format!(
                r#"{{"sub":"user-frac","exp":{}.5,"iat":{}.5,"cap":{}.5}}"#,
                now + 800,
                now - 600,
                now + 7200
            ))
            .expect("fractional claims parse");
            let token = hs256(&claims);
            let resp = run(cookie_cfg(), req_with(&[], &[("ipe_sid", &token)])).await;
            assert_eq!(resp.status, 200, "a fractional-date token dispatches");
            assert!(
                resp.cookies.iter().any(|c| c.starts_with("ipe_sid=")),
                "a past-threshold fractional `exp` re-issues: {:?}",
                resp.cookies
            );
        }

        /// A fresh cookie token (exp well beyond the re-issue threshold) must
        /// not produce a Set-Cookie — the throttle holds, no unnecessary write.
        #[tokio::test]
        async fn fresh_cookie_not_past_threshold_has_no_reissue_set_cookie() {
            let now = now_secs();
            // exp = now + 3600; threshold = exp - 900 = now + 2700.
            // now < now + 2700, so past_threshold = false.
            let token = hs256(&serde_json::json!({
                "sub": "user-fresh",
                "exp": now + 3600,
                "iat": now - 60,
                "cap": now + 7200,
            }));
            let resp = run(cookie_cfg(), req_with(&[], &[("ipe_sid", &token)])).await;
            assert_eq!(resp.status, 200, "valid token must dispatch the handler");
            assert!(
                resp.cookies.is_empty(),
                "no re-issue cookie for a fresh token that has not crossed the threshold: {:?}",
                resp.cookies
            );
        }

        /// Bearer tokens are API credentials; re-issue is the client's
        /// responsibility. The authed-route middleware must never attach a
        /// Set-Cookie for a bearer-source token, even when the exp is past the
        /// re-issue threshold.
        #[tokio::test]
        async fn bearer_past_threshold_never_gets_reissue_set_cookie() {
            let now = now_secs();
            let token = hs256(&serde_json::json!({
                "sub": "user-api",
                "exp": now + 800,
                "iat": now - 600,
                "cap": now + 7200,
            }));
            let req = req_with(&[("authorization", &format!("Bearer {token}"))], &[]);
            let resp = run(bearer_cfg(), req).await;
            assert_eq!(resp.status, 200, "valid bearer token must dispatch");
            assert!(
                resp.cookies.is_empty(),
                "bearer-source must never get a re-issue Set-Cookie: {:?}",
                resp.cookies
            );
        }

        // ── reissue Secure parity ──────────────────────────────────────────

        /// `reissue_set_cookie_with` truth-table under a dev intent:
        ///   (`is_https`=true)  → Secure
        ///   (`is_https`=false) → no Secure
        /// Mirrors the combined gate in `page_response`:
        /// a re-issued cookie must never be less-Secure than the initial one.
        #[test]
        fn reissue_set_cookie_secure_matches_initial_gate() {
            let dev = crate::telemetry::test_dev_intent();
            let floor = cookie_secure_floor_with(Some(&dev));

            let c_https = reissue_set_cookie_with(&sid("ipe_sid"), "tok", 1800, true);
            assert!(
                c_https.contains("; Secure"),
                "reissue behind TLS proxy must carry Secure: {c_https}"
            );

            let c_plain = reissue_set_cookie_with(&sid("ipe_sid"), "tok", 1800, floor);
            assert!(
                !c_plain.contains("; Secure"),
                "reissue over plain HTTP in dev must NOT carry Secure: {c_plain}"
            );
        }

        /// A trusted `X-Forwarded-Proto: https` header produces a re-issued
        /// cookie that carries `Secure`, on every build.
        ///
        /// Uses `request_is_https_with_trust(..., true)` directly to bypass the
        /// `OnceLock`-cached `trust_proxy_headers()` without mutating process env.
        #[test]
        fn reissue_set_cookie_https_proxy_sets_secure() {
            let mut headers = HashMap::new();
            headers.insert("x-forwarded-proto".to_string(), "https".to_string());
            let is_https = request_is_https_with_trust(&headers, true);
            assert!(is_https, "trusted HTTPS header must be detected");

            let cookie = reissue_set_cookie(&sid("ipe_sid"), "tok", 1800, is_https);
            assert!(
                cookie.contains("; Secure"),
                "reissue with HTTPS proxy signal must carry Secure: {cookie}"
            );
        }

        // A release binary under `ENV=dev` re-issues a `Secure` cookie even
        // over plain HTTP.
        #[cfg(not(feature = "dev-posture"))]
        #[test]
        fn reissue_set_cookie_secure_on_release_under_env_dev() {
            crate::system::locked_set_var("ENV", "dev");
            let cookie = reissue_set_cookie(&sid("ipe_sid"), "tok", 1800, false);
            crate::system::locked_remove_var("ENV");
            assert!(cookie.contains("; Secure"), "{cookie}");
        }

        /// Non-proxy default: no `X-Forwarded-Proto`, trust=false → no Secure
        /// on a dev-intent reissue.
        #[test]
        fn reissue_set_cookie_plain_http_no_secure() {
            let headers = HashMap::new();
            let is_https = request_is_https_with_trust(&headers, false);
            assert!(!is_https);

            let dev = crate::telemetry::test_dev_intent();
            let secure = cookie_secure_floor_with(Some(&dev)) || is_https;
            let cookie = reissue_set_cookie_with(&sid("ipe_sid"), "tok", 1800, secure);
            assert!(
                !cookie.contains("; Secure"),
                "reissue over plain HTTP must NOT carry Secure: {cookie}"
            );
        }

        // ── revocation-gated channels ────────────────────────────────────

        /// An in-memory WebSocket: the test feeds `inbound` and reads what the
        /// loop sends from `outbound`.
        struct MemSocket {
            inbound: tokio::sync::mpsc::UnboundedReceiver<axum::extract::ws::Message>,
            outbound: tokio::sync::mpsc::UnboundedSender<axum::extract::ws::Message>,
        }

        impl futures_util::Stream for MemSocket {
            type Item = Result<axum::extract::ws::Message, axum::Error>;

            fn poll_next(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                self.get_mut()
                    .inbound
                    .poll_recv(cx)
                    .map(|frame| frame.map(Ok))
            }
        }

        impl futures_util::Sink<axum::extract::ws::Message> for MemSocket {
            type Error = tokio::sync::mpsc::error::SendError<axum::extract::ws::Message>;

            fn poll_ready(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn start_send(
                self: Pin<&mut Self>,
                item: axum::extract::ws::Message,
            ) -> Result<(), Self::Error> {
                self.get_mut().outbound.send(item)
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }
        }

        /// The test's end of a socket `ws_loop` serves.
        struct WsPeer {
            id: i64,
            to_server: tokio::sync::mpsc::UnboundedSender<axum::extract::ws::Message>,
            from_server: tokio::sync::mpsc::UnboundedReceiver<axum::extract::ws::Message>,
            /// Every text `onMessage` was handed.
            delivered: tokio::sync::mpsc::UnboundedReceiver<String>,
            /// One unit per `onConnect` run.
            connected: tokio::sync::mpsc::UnboundedReceiver<()>,
            /// One unit per `onClose` run.
            closed: tokio::sync::mpsc::UnboundedReceiver<()>,
        }

        /// What the served socket's `onMessage` does with a text before it
        /// reports it delivered.
        #[derive(Clone)]
        enum OnMessage {
            /// Nothing.
            Report,
            /// Verify the text as a token.
            Verify,
            /// Report, then wait for the notify.
            Hold(Arc<tokio::sync::Notify>),
        }

        /// Spawn `ws_loop` over an in-memory socket under `credentials` and
        /// `gate`, without waiting for it to connect.
        fn spawn_ws(
            credentials: ChannelCredentials,
            gate: Option<ChannelGate>,
            on_message: OnMessage,
        ) -> WsPeer {
            spawn_ws_draining(credentials, gate, on_message, shutdown::Drain::never())
        }

        /// [`spawn_ws`] whose loop ends when `drain` drains.
        fn spawn_ws_draining(
            credentials: ChannelCredentials,
            gate: Option<ChannelGate>,
            on_message: OnMessage,
            drain: shutdown::Drain,
        ) -> WsPeer {
            let (to_server, inbound) = tokio::sync::mpsc::unbounded_channel();
            let (outbound, from_server) = tokio::sync::mpsc::unbounded_channel();
            let (seen, delivered) = tokio::sync::mpsc::unbounded_channel::<String>();
            let (connected_tx, connected) = tokio::sync::mpsc::unbounded_channel::<()>();
            let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel::<()>();
            let cfg = WsServerCfg {
                onConnect: Arc::new(move |_: WsHandle| {
                    let _ = connected_tx.send(());
                    Box::pin(async { ok_res(()) }) as IpeTask<String, ()>
                }),
                onClose: Arc::new(move |_: WsHandle| {
                    let _ = closed_tx.send(());
                    Box::pin(async { ok_res(()) }) as IpeTask<String, ()>
                }),
                onMessage: Arc::new(move |_: WsHandle, text: String| {
                    let seen = seen.clone();
                    match on_message.clone() {
                        OnMessage::Report => {}
                        OnMessage::Verify => {
                            // Verified at call time, as an emitted callback's
                            // pure code is.
                            let _ =
                                crate::auth::auth_verify_token(SECRET.to_string(), text.clone());
                        }
                        OnMessage::Hold(release) => {
                            let _ = seen.send(text);
                            return Box::pin(async move {
                                release.notified().await;
                                ok_res(())
                            }) as IpeTask<String, ()>;
                        }
                    }
                    let _ = seen.send(text);
                    Box::pin(async { ok_res(()) }) as IpeTask<String, ()>
                }),
                ..ws_server_default_cfg::<String>()
            };
            let ceilings = WsCeilings {
                send_buffer: 16,
                max_connections: usize::MAX,
                heartbeat_secs: 30,
            };
            let id = WS_NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let socket = MemSocket { inbound, outbound };
            tokio::spawn(ws_loop(socket, cfg, id, ceilings, credentials, gate, drain));
            WsPeer {
                id,
                to_server,
                from_server,
                delivered,
                connected,
                closed,
            }
        }

        /// Serve an in-memory socket under `credentials` and `gate` and wait
        /// until `onConnect` ran, so the loop is idle in its select when this
        /// returns.
        async fn serve_ws_with(
            credentials: ChannelCredentials,
            gate: Option<ChannelGate>,
            on_message: OnMessage,
        ) -> WsPeer {
            let mut peer = spawn_ws(credentials, gate, on_message);
            let opened = tokio::time::timeout(RECHECK_COALESCE, peer.connected.recv()).await;
            assert!(matches!(opened, Ok(Some(()))), "the socket must connect");
            peer
        }

        /// [`serve_ws_with`] whose `onMessage` only reports.
        async fn serve_ws(credentials: ChannelCredentials, gate: Option<ChannelGate>) -> WsPeer {
            serve_ws_with(credentials, gate, OnMessage::Report).await
        }

        /// Whether `frame` is the close a gated socket sends on a denial.
        fn is_denied_close(frame: Option<&axum::extract::ws::Message>) -> bool {
            matches!(
                frame,
                Some(axum::extract::ws::Message::Close(Some(close)))
                    if close.code == axum::extract::ws::close_code::POLICY
                        && close.reason == "credential revoked"
            )
        }

        /// The next frame the server sends within `wait`, if any.
        async fn next_frame(
            peer: &mut WsPeer,
            wait: std::time::Duration,
        ) -> Option<axum::extract::ws::Message> {
            tokio::time::timeout(wait, peer.from_server.recv())
                .await
                .ok()
                .flatten()
        }

        /// Claims for a fresh session of `subject`, whose deadline is `cap`.
        fn session_claims(subject: &str, jti: &str, cap: i64) -> serde_json::Value {
            let now = crate::jwt::now_unix_seconds();
            serde_json::json!({
                "sub": subject,
                "jti": jti,
                "iat": now,
                "exp": now + 3600,
                "cap": cap,
            })
        }

        /// What a socket opened by an armed authed route would carry, for a
        /// request bearing `claims`: the request's credentials and its gate.
        async fn gate_of_authed_request(
            claims: &serde_json::Value,
        ) -> (ChannelCredentials, Option<ChannelGate>) {
            type Opened = (ChannelCredentials, Option<ChannelGate>);
            let slot: Arc<Mutex<Option<Opened>>> = Arc::default();
            let sink = Arc::clone(&slot);
            let route = server_get_authed::<String, _>(
                "/ws".to_string(),
                server_with_revocation(1, bearer_cfg()),
                move |_req, _p| {
                    let credentials = ChannelCredentials::of_request();
                    let gate = ChannelGate::open(&credentials).ok().flatten();
                    if let Ok(mut held) = sink.lock() {
                        *held = Some((credentials, gate));
                    }
                    Box::pin(std::future::ready(ok_res(server_text(String::new()))))
                },
            );
            let RouteTarget::Handler(h) = route.target else {
                panic!("a GET route carries a handler");
            };
            let admitted = dispatch(&h, bearer_req(claims))
                .await
                .0
                .map_or(500, |resp| resp.status);
            assert_eq!(admitted, 200, "the armed route admits the token");
            let opened = slot.lock().ok().and_then(|mut held| held.take());
            opened.expect("the route handler opened the channel")
        }

        #[tokio::test(start_paused = true)]
        async fn ws_closes_1008_after_revoke_session() {
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("ws-revoke-subject", "ws-revoke-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            assert!(gate.is_some(), "a socket of an armed authed route is gated");
            let mut peer = serve_ws(credentials, gate).await;
            crate::revocation::revoke_session("ws-revoke-jti".to_string(), cap).expect("revoke");
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "an idle socket closes 1008 within the coalesce bound: {frame:?}"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn ws_inbound_frame_after_revoke_never_reaches_handler() {
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("ws-inbound-subject", "ws-inbound-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            assert!(gate.is_some(), "a socket of an armed authed route is gated");
            let mut peer = serve_ws(credentials, gate).await;
            let before = axum::extract::ws::Message::Text("before".into());
            assert!(peer.to_server.send(before).is_ok());
            let delivered = tokio::time::timeout(RECHECK_COALESCE, peer.delivered.recv()).await;
            assert!(
                matches!(delivered, Ok(Some(ref text)) if text == "before"),
                "a frame before the revocation reaches the handler"
            );
            crate::revocation::revoke_session("ws-inbound-jti".to_string(), cap).expect("revoke");
            let after = axum::extract::ws::Message::Text("after".into());
            assert!(peer.to_server.send(after).is_ok());
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "the socket closes 1008: {frame:?}"
            );
            assert!(
                peer.delivered.try_recv().is_err(),
                "a frame after the revocation never reaches the handler"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn ws_closes_at_credential_deadline() {
            let cap = crate::jwt::now_unix_seconds() + 3;
            let claims = session_claims("ws-deadline-subject", "ws-deadline-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            assert!(gate.is_some(), "a socket of an armed authed route is gated");
            let mut peer = serve_ws(credentials, gate).await;
            let frame = next_frame(&mut peer, std::time::Duration::from_secs(10)).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "the socket closes 1008 at its deadline, before any heartbeat: {frame:?}"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn stream_ends_after_revoke_and_its_handler_is_aborted() {
            use futures_util::StreamExt;
            type Emits = (IpeResult<String, ()>, IpeResult<String, ()>);
            struct Dropped(Arc<std::sync::atomic::AtomicBool>);
            impl Drop for Dropped {
                fn drop(&mut self) {
                    self.0.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let dropped_in = Arc::clone(&dropped);
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("stream-revoke-subject", "stream-revoke-jti", cap);
            let (emits_tx, mut emits) = tokio::sync::mpsc::unbounded_channel::<Emits>();
            let release = Arc::new(tokio::sync::Notify::new());
            let release_in = Arc::clone(&release);
            let route = server_get_authed::<String, _>(
                "/stream".to_string(),
                server_with_revocation(1, bearer_cfg()),
                move |_req, _p| {
                    let emits_tx = emits_tx.clone();
                    let release = Arc::clone(&release_in);
                    let dropped = Arc::clone(&dropped_in);
                    crate::server_stream::server_stream_stream::<String, _>(
                        "text/plain".to_string(),
                        move |writer| {
                            let emits_tx = emits_tx.clone();
                            let release = Arc::clone(&release);
                            let guard = Dropped(Arc::clone(&dropped));
                            Box::pin(async move {
                                let _guard = guard;
                                let first = crate::server_stream::server_stream_emit::<String>(
                                    "first".to_string(),
                                    writer,
                                )
                                .await;
                                release.notified().await;
                                let late = crate::server_stream::server_stream_emit::<String>(
                                    "late".to_string(),
                                    writer,
                                )
                                .await;
                                let _ = emits_tx.send((first, late));
                                ok_res(())
                            }) as IpeTask<String, ()>
                        },
                    )
                },
            );
            assert!(matches!(route.target, RouteTarget::Handler(_)));
            let RouteTarget::Handler(h) = route.target else {
                return;
            };
            let (resp, streams) = dispatch(&h, bearer_req(&claims)).await;
            let resp = resp.expect("the stream handler answers");
            let streamed = to_axum_response(resp, streams);
            assert_eq!(streamed.status(), axum::http::StatusCode::OK);
            let mut body = streamed.into_body().into_data_stream();
            let first = tokio::time::timeout(RECHECK_COALESCE, body.next()).await;
            assert!(
                matches!(first, Ok(Some(Ok(ref chunk))) if chunk.to_vec() == b"first"),
                "a chunk before the revocation reaches the client"
            );
            crate::revocation::revoke_session("stream-revoke-jti".to_string(), cap)
                .expect("revoke");
            let ended = tokio::time::timeout(2 * RECHECK_COALESCE, body.next()).await;
            assert!(
                matches!(ended, Ok(None)),
                "the body ends within the coalesce bound"
            );
            let aborted = tokio::time::timeout(RECHECK_COALESCE, async {
                while !dropped.load(std::sync::atomic::Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await;
            assert!(
                aborted.is_ok(),
                "a body that ended on the revocation aborts its handler"
            );
            release.notify_one();
            let reported = tokio::time::timeout(RECHECK_COALESCE, emits.recv()).await;
            assert!(
                reported.is_err(),
                "the aborted handler never reaches its late emit: {reported:?}"
            );
        }

        /// The credentials and gate of a socket an armed request that bound
        /// nothing opens.
        async fn gate_of_unauthed_request() -> (ChannelCredentials, Option<ChannelGate>) {
            crate::revocation::arm_process();
            in_request_scope(async {
                let credentials = ChannelCredentials::of_request();
                let gate = ChannelGate::open(&credentials);
                assert!(
                    matches!(gate, Ok(Some(_))),
                    "an armed request that bound nothing still gates its socket"
                );
                (credentials, gate.ok().flatten())
            })
            .await
        }

        #[tokio::test(start_paused = true)]
        async fn unauthed_ws_stays_open_on_an_unrelated_revoke() {
            let (credentials, gate) = gate_of_unauthed_request().await;
            let mut peer = serve_ws(credentials, gate).await;
            crate::revocation::revoke_session(
                "ws-unauthed-jti".to_string(),
                crate::jwt::now_unix_seconds() + 7200,
            )
            .expect("revoke");
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(frame.is_none(), "an ungated socket stays open: {frame:?}");
            let text = axum::extract::ws::Message::Text("still-open".into());
            assert!(peer.to_server.send(text).is_ok());
            let delivered = tokio::time::timeout(RECHECK_COALESCE, peer.delivered.recv()).await;
            assert!(
                matches!(delivered, Ok(Some(ref text)) if text == "still-open"),
                "an ungated socket keeps delivering frames"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn public_route_ws_after_verify_token_closes_on_revoke() {
            crate::revocation::arm_process();
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims("ws-public-subject", "ws-public-jti", cap));
            let (credentials, gate) = in_request_scope(async move {
                let verified = crate::auth::auth_verify_token(SECRET.to_string(), token);
                assert!(
                    matches!(verified, IpeResult::Ok(_)),
                    "the armed kernel admits the token"
                );
                let credentials = ChannelCredentials::of_request();
                let gate = ChannelGate::open(&credentials).ok().flatten();
                (credentials, gate)
            })
            .await;
            assert!(
                gate.is_some(),
                "a public route that verified a token gates its socket"
            );
            let mut peer = serve_ws(credentials, gate).await;
            crate::revocation::revoke_subject("ws-public-subject".to_string()).expect("revoke");
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "revoking the verified token closes the socket 1008: {frame:?}"
            );
        }

        /// Serve one GET of `/public` through a real `method_router` whose
        /// route handler is `h`, and answer the response body.
        async fn serve_public(h: ErasedHandler) -> String {
            use tower::ServiceExt;
            let app = behind_listener(endpoint_router("/public", h));
            let wire = axum::http::Request::builder()
                .method("GET")
                .uri("/public")
                .body(axum::body::Body::empty())
                .expect("a buildable request");
            let resp = match app.oneshot(wire).await {
                Ok(r) => r,
                Err(e) => match e {},
            };
            axum_body_string(resp).await
        }

        #[tokio::test]
        async fn verify_token_called_in_handler_body_binds_to_the_request() {
            crate::revocation::arm_process();
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims("dispatch-subject", "dispatch-jti", cap));
            // The verify runs when the handler is CALLED, as an emitted
            // handler's pure code does, not when its task is awaited.
            let route =
                server_get::<String, _>("/public".to_string(), move |_req: ServerRequest| {
                    let verified = matches!(
                        crate::auth::auth_verify_token(SECRET.to_string(), token.clone()),
                        IpeResult::Ok(_)
                    );
                    let bound = request_bindings()
                        .and_then(|bindings| bindings.lock().ok().map(|held| held.len()))
                        .unwrap_or_default();
                    Box::pin(std::future::ready(ok_res::<String, _>(server_text(
                        format!("{verified}|{bound}"),
                    )))) as IpeTask<String, ServerResponse>
                });
            let RouteTarget::Handler(h) = route.target else {
                panic!("a GET route carries a handler");
            };
            assert_eq!(
                serve_public(h).await,
                "true|1",
                "a token verified in the handler body binds to the request it answers"
            );
        }

        /// A task that answers whether it runs inside the binding set `outer`.
        fn probe_scope(
            outer: Option<Arc<Mutex<crate::revocation::SessionBindings>>>,
        ) -> IpeTask<String, bool> {
            Box::pin(async move {
                ok_res::<String, _>(matches!(
                    (request_bindings(), outer),
                    (Some(inner), Some(outer)) if Arc::ptr_eq(&inner, &outer)
                ))
            })
        }

        #[tokio::test]
        async fn parallel_tasks_inside_a_request_keep_its_scope() {
            let seen = in_request_scope(async {
                let probe = probe_scope(request_bindings());
                crate::task::task_parallel(vec![probe]).await
            })
            .await;
            assert!(
                matches!(seen, IpeResult::Ok(ref all) if all.as_slice() == [true]),
                "a Task.parallel branch binds into the request that spawned it"
            );
        }

        #[tokio::test]
        async fn task_run_inside_a_request_keeps_its_scope() {
            let seen = in_request_scope(async {
                let probe = probe_scope(request_bindings());
                crate::task::task_run(probe)
            })
            .await;
            assert!(
                matches!(seen, IpeResult::Ok(true)),
                "a Task.run inside a handler binds into the request that called it"
            );
        }

        #[tokio::test]
        async fn token_verified_in_a_parallel_task_binds_to_the_request() {
            crate::revocation::arm_process();
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims("parallel-subject", "parallel-jti", cap));
            let bound = in_request_scope(async move {
                let verify: IpeTask<String, bool> = Box::pin(async move {
                    ok_res::<String, _>(matches!(
                        crate::auth::auth_verify_token(SECRET.to_string(), token),
                        IpeResult::Ok(_)
                    ))
                });
                let verified = crate::task::task_parallel(vec![verify]).await;
                assert!(
                    matches!(verified, IpeResult::Ok(ref all) if all.as_slice() == [true]),
                    "the armed kernel admits the token"
                );
                request_bindings()
                    .and_then(|bindings| bindings.lock().ok().map(|held| held.len()))
                    .unwrap_or_default()
            })
            .await;
            assert_eq!(
                bound, 1,
                "a token a Task.parallel branch verified binds to the request"
            );
        }

        #[tokio::test]
        async fn ffi_spawned_task_inside_a_request_keeps_its_scope() {
            let seen = in_request_scope(async {
                let outer = request_bindings();
                crate::task::ffi_spawn_guarded(async move {
                    matches!(
                        (request_bindings(), outer),
                        (Some(inner), Some(outer)) if Arc::ptr_eq(&inner, &outer)
                    )
                })
                .await
            })
            .await;
            assert!(
                matches!(seen, Ok(true)),
                "a guarded foreign task binds into the request that spawned it"
            );
        }

        #[tokio::test]
        async fn armed_channel_opened_outside_any_request_is_refused() {
            crate::revocation::arm_process();
            assert!(
                matches!(
                    ChannelGate::open(&ChannelCredentials::of_request()),
                    Err(ChannelDenial::Unscoped)
                ),
                "an armed process cannot know the credentials of an unscoped channel"
            );
        }

        /// A stream table with no binding set beside it: the serve-time gate
        /// of an armed process still refuses the unscoped credentials.
        #[tokio::test]
        async fn armed_stream_without_request_credentials_answers_401() {
            use std::sync::atomic::{AtomicBool, Ordering};
            crate::revocation::arm_process();
            let ran = Arc::new(AtomicBool::new(false));
            let ran_in = Arc::clone(&ran);
            let (registered, streams) = crate::server_stream::in_stream_scope(
                crate::server_stream::server_stream_stream::<String, _>(
                    "text/plain".to_string(),
                    move |_writer| {
                        ran_in.store(true, Ordering::SeqCst);
                        Box::pin(async { ok_res(()) }) as IpeTask<String, ()>
                    },
                ),
            )
            .await;
            assert!(matches!(registered, IpeResult::Ok(_)));
            let IpeResult::Ok(resp) = registered else {
                return;
            };
            let served = to_axum_response(resp, streams);
            assert_eq!(
                served.status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "an unscoped stream of an armed process is refused"
            );
            tokio::task::yield_now().await;
            assert!(
                !ran.load(Ordering::SeqCst),
                "a refused stream never runs its handler"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn token_verified_in_on_message_closes_the_socket_on_revoke() {
            let (credentials, gate) = gate_of_unauthed_request().await;
            let mut peer = serve_ws_with(credentials, gate, OnMessage::Verify).await;
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims("ws-message-subject", "ws-message-jti", cap));
            assert!(
                peer.to_server
                    .send(axum::extract::ws::Message::Text(token.into()))
                    .is_ok()
            );
            let delivered = tokio::time::timeout(RECHECK_COALESCE, peer.delivered.recv()).await;
            assert!(
                matches!(delivered, Ok(Some(_))),
                "the token reaches onMessage"
            );
            crate::revocation::revoke_subject("ws-message-subject".to_string()).expect("revoke");
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "a token onMessage verified binds to the socket: {frame:?}"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn token_verified_in_stream_handler_ends_the_body_on_revoke() {
            use futures_util::StreamExt;
            crate::revocation::arm_process();
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims(
                "stream-body-subject",
                "stream-body-jti",
                cap,
            ));
            let release = Arc::new(tokio::sync::Notify::new());
            let release_in = Arc::clone(&release);
            let route =
                server_get::<String, _>("/stream".to_string(), move |_req: ServerRequest| {
                    let token = token.clone();
                    let release = Arc::clone(&release_in);
                    crate::server_stream::server_stream_stream::<String, _>(
                        "text/plain".to_string(),
                        move |writer| {
                            // Verified at call time, as an emitted handler's pure
                            // code is.
                            let _ =
                                crate::auth::auth_verify_token(SECRET.to_string(), token.clone());
                            let release = Arc::clone(&release);
                            Box::pin(async move {
                                let _ = crate::server_stream::server_stream_emit::<String>(
                                    "first".to_string(),
                                    writer,
                                )
                                .await;
                                release.notified().await;
                                let _ = crate::server_stream::server_stream_emit::<String>(
                                    "late".to_string(),
                                    writer,
                                )
                                .await;
                                ok_res(())
                            }) as IpeTask<String, ()>
                        },
                    )
                });
            let RouteTarget::Handler(h) = route.target else {
                panic!("a GET route carries a handler");
            };
            let (resp, streams) = dispatch(&h, req_with(&[], &[])).await;
            let resp = resp.expect("the stream handler answers");
            let mut body = to_axum_response(resp, streams)
                .into_body()
                .into_data_stream();
            let first = tokio::time::timeout(RECHECK_COALESCE, body.next()).await;
            assert!(
                matches!(first, Ok(Some(Ok(ref chunk))) if chunk.to_vec() == b"first"),
                "a chunk before the revocation reaches the client"
            );
            crate::revocation::revoke_subject("stream-body-subject".to_string()).expect("revoke");
            let ended = tokio::time::timeout(2 * RECHECK_COALESCE, body.next()).await;
            release.notify_one();
            assert!(
                matches!(ended, Ok(None)),
                "a token the stream handler verified binds to the stream: {ended:?}"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn an_owed_denial_closes_before_a_queued_frame_is_sent() {
            // Repeated so an unordered select would send the queued frame
            // first on some round.
            for round in 0..8 {
                let cap = crate::jwt::now_unix_seconds() + 7200;
                let jti = format!("ws-owed-jti-{round}");
                let claims = session_claims(&format!("ws-owed-subject-{round}"), &jti, cap);
                let (credentials, gate) = gate_of_authed_request(&claims).await;
                assert!(gate.is_some(), "a socket of an armed authed route is gated");
                let release = Arc::new(tokio::sync::Notify::new());
                let mut peer =
                    serve_ws_with(credentials, gate, OnMessage::Hold(Arc::clone(&release))).await;
                let hold = axum::extract::ws::Message::Text("hold".into());
                assert!(peer.to_server.send(hold).is_ok());
                let held = tokio::time::timeout(RECHECK_COALESCE, peer.delivered.recv()).await;
                assert!(matches!(held, Ok(Some(_))), "onMessage is holding the loop");
                crate::revocation::revoke_session(jti, cap).expect("revoke");
                let queued = ws_registry()
                    .lock()
                    .ok()
                    .and_then(|reg| reg.get(&peer.id).cloned())
                    .map(|tx| tx.try_send(WsOut::Text("queued".to_string())).is_ok());
                assert_eq!(queued, Some(true), "a frame is queued for the socket");
                tokio::time::advance(2 * RECHECK_COALESCE).await;
                release.notify_one();
                let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
                assert!(
                    is_denied_close(frame.as_ref()),
                    "round {round}: the owed denial closes before the queued frame: {frame:?}"
                );
            }
        }

        #[tokio::test(start_paused = true)]
        async fn ws_binary_frame_after_revoke_never_reaches_handler() {
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("ws-binary-subject", "ws-binary-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            let mut peer = serve_ws(credentials, gate).await;
            crate::revocation::revoke_session("ws-binary-jti".to_string(), cap).expect("revoke");
            let after =
                axum::extract::ws::Message::Binary(axum::body::Bytes::from_static(b"after"));
            assert!(peer.to_server.send(after).is_ok());
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "the socket closes 1008: {frame:?}"
            );
            assert!(
                peer.delivered.try_recv().is_err(),
                "a binary frame after the revocation never reaches the handler"
            );
        }

        #[tokio::test]
        async fn a_draining_socket_closes_going_away_and_runs_on_close() {
            let exited = Arc::new(std::sync::atomic::AtomicI32::new(0));
            let (armed, signals) = shutdown::tests::armed_with(
                shutdown::ShutdownPlan::bare("test"),
                std::time::Duration::from_secs(5),
                exited,
            );
            let mut peer = spawn_ws_draining(
                ChannelCredentials::of_request(),
                None,
                OnMessage::Report,
                armed.drain(),
            );
            let opened = tokio::time::timeout(RECHECK_COALESCE, peer.connected.recv()).await;
            assert!(matches!(opened, Ok(Some(()))), "the socket must connect");
            assert!(signals.send(shutdown::Signal::Terminate).await.is_ok());
            let frame = next_frame(&mut peer, shutdown::WS_CLOSE_DEADLINE).await;
            assert!(
                matches!(
                    frame,
                    Some(axum::extract::ws::Message::Close(Some(ref close)))
                        if close.code == axum::extract::ws::close_code::AWAY
                ),
                "a draining socket closes 1001: {frame:?}"
            );
            let closed = tokio::time::timeout(RECHECK_COALESCE, peer.closed.recv()).await;
            assert!(matches!(closed, Ok(Some(()))), "onClose runs on the drain");
            armed.settle_live().await;
            assert_eq!(armed.live_count(), 0, "the socket's live count clears");
        }

        #[tokio::test(start_paused = true)]
        async fn ws_revoked_before_the_loop_never_connects() {
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("ws-early-subject", "ws-early-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            crate::revocation::revoke_session("ws-early-jti".to_string(), cap).expect("revoke");
            let mut peer = spawn_ws(credentials, gate, OnMessage::Report);
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "the socket closes 1008 before it registers: {frame:?}"
            );
            assert!(
                peer.connected.try_recv().is_err(),
                "a socket revoked before the loop never runs onConnect"
            );
        }

        #[tokio::test]
        async fn ws_upgrade_after_revoke_answers_401() {
            crate::revocation::arm_process();
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let token = hs256(&session_claims("ws-upgrade-subject", "ws-upgrade-jti", cap));
            let status = in_request_scope(async move {
                let verified = crate::auth::auth_verify_token(SECRET.to_string(), token);
                assert!(matches!(verified, IpeResult::Ok(_)), "the token verifies");
                crate::revocation::revoke_session("ws-upgrade-jti".to_string(), cap)
                    .expect("revoke");
                let mut cfg = ws_server_default_cfg::<String>();
                cfg.originPatterns = vec!["https://victim.example".to_owned()];
                let req = mk_ws_req(&[
                    ("origin", "https://victim.example"),
                    ("host", "victim.example"),
                ]);
                match server_web_socket_upgrade::<String>(req, cfg).await {
                    IpeResult::Ok(resp) => resp.status,
                    IpeResult::Err(_) => 500,
                }
            })
            .await;
            assert_eq!(
                status, 401,
                "an upgrade whose credential was revoked is refused"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn ws_poisoned_binding_set_closes_on_the_next_frame() {
            let cap = crate::jwt::now_unix_seconds() + 7200;
            let claims = session_claims("ws-poison-subject", "ws-poison-jti", cap);
            let (credentials, gate) = gate_of_authed_request(&claims).await;
            let ChannelCredentials::Request(bindings) = credentials.clone() else {
                panic!("an authed request carries its binding set");
            };
            let mut peer = serve_ws(credentials, gate).await;
            let poisoner = std::thread::Builder::new().spawn(move || {
                let _held = bindings.lock();
                panic!("poison the binding set");
            });
            let Ok(poisoner) = poisoner else {
                panic!("the OS refused the poisoning thread");
            };
            let poisoned = poisoner.join();
            assert!(poisoned.is_err(), "the binding set is poisoned");
            let text = axum::extract::ws::Message::Text("after".into());
            assert!(peer.to_server.send(text).is_ok());
            let frame = next_frame(&mut peer, 2 * RECHECK_COALESCE).await;
            assert!(
                is_denied_close(frame.as_ref()),
                "a gate that cannot read its binding set denies: {frame:?}"
            );
            assert!(
                peer.delivered.try_recv().is_err(),
                "the frame never reaches the handler"
            );
        }
    }
}

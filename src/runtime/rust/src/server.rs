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

use crate::redact::{Redacted, redacting_debug};

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
        Some((m, p)) if !m.is_empty() => (m.trim().to_uppercase(), p.trim().to_string()),
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
/// a no-op.
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
/// Revocation gate (when `RevocationMode::Store`): the store is queried AFTER
/// signature + expiry verification and BEFORE the `Principal` is minted. Deny
/// on `Verdict::Revoked`, on `Verdict::Unknown`, and on any store error
/// (fail-closed). Only `Verdict::Active` allows the request through.
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
            let claims: HashMap<String, String> =
                match crate::auth::auth_verify_token::<String>(secret.clone(), token) {
                    IpeResult::Ok(c) => c,
                    IpeResult::Err(_) => return ok_res(unauthorized()),
                };
            let Some(subject) = claims.get(&cfg.subject_claim).filter(|s| !s.is_empty()) else {
                return ok_res(unauthorized());
            };

            // Revocation gate — consulted only when the mode is `Store`.
            // Runs AFTER token verification and BEFORE `Principal` mint.
            // Fail-closed: deny on Revoked, Unknown, and any store error.
            if cfg.revocation_mode == crate::app_config::RevocationMode::Store {
                let jti = claims.get("jti").map(String::as_str).unwrap_or("");
                match crate::revocation::is_revoked(subject, jti) {
                    crate::revocation::Verdict::Active => {}
                    // Revoked or Unknown both deny — fail-closed.
                    crate::revocation::Verdict::Revoked | crate::revocation::Verdict::Unknown => {
                        return ok_res(unauthorized());
                    }
                }
            }

            // Carry the verified claims into the principal so the Ipê read
            // accessors (`Auth.claim` / `Auth.hasRole` / `Auth.memberOf`) can
            // answer principal-side questions. These are the token's own
            // verified payload — the same bearer-readable strings the caller
            // presented — so nothing new is exposed. `BTreeMap` keeps the
            // read-back deterministic.
            let principal = crate::principal::principal_mint_with_claims(
                subject.clone(),
                claims.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            );

            // Sliding re-issue — cookie-source only (bearer tokens are API
            // credentials; the client manages re-issue itself via re-auth).
            let reissue_cookie: Option<SetCookie> =
                if let TokenSource::Cookie(ref name) = cfg.source {
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
                        // Parse exp from the verified claims string representation.
                        let past_threshold = claims
                            .get("exp")
                            .and_then(|s| s.parse::<i64>().ok())
                            .map(|exp| now > exp.saturating_sub(slide_i64 / 2))
                            .unwrap_or(false);
                        if past_threshold && now < ctx.cap {
                            // Extra claims to carry into the re-issued token (all
                            // verified claims except the time anchors and subject —
                            // those come from the ReissueContext).
                            let extra: HashMap<String, String> = claims
                                .iter()
                                .filter(|(k, _)| {
                                    // Time anchors and session-identity fields come from
                                    // ReissueContext verbatim; skip them in extra_claims.
                                    *k != "exp"
                                        && *k != "iat"
                                        && *k != "cap"
                                        && *k != "jti"
                                        && *k != "sub"
                                })
                                .map(|(k, v)| (k.clone(), v.clone()))
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
    /// bytes that are not UTF-8, an over-cap component or too many query pairs).
    BadRequest,
    /// The request-body ceiling's environment value is malformed.
    Unavailable,
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
        }
    }
}

/// Decode the request's query string, refusing it whole on any defect.
fn parse_query(q: Option<&str>) -> Result<HashMap<String, String>, crate::encoding::QueryRefusal> {
    q.map_or_else(|| Ok(HashMap::new()), crate::encoding::decode_form_query)
}

/// A request URI parsed once by the strict core: its path split and decoded
/// segment by segment, its query decoded under the form grammar.
pub(crate) struct StrictUrl {
    /// The decoded request path; every route matcher reads this, never the raw
    /// path text.
    pub(crate) path: crate::encoding::DecodedPath,
    /// The decoded query.
    pub(crate) query: HashMap<String, String>,
}

/// Parse a request URI once, refusing it whole when its path or query is not
/// well-formed.
///
/// The path must be a well-formed RFC 3986 path: every raw segment decodes
/// through `decode_component` under the path grammar (`DecodedPath::parse`,
/// the parse the Ipe.Web route matcher reads its segments from, so the gate and
/// the matcher refuse the same paths). This is also what makes the Ipe.Server
/// path parameters sound: the router hands back each parameter already
/// percent-decoded once by a lenient decoder, and on a path that passes this
/// parse that decoding is byte-for-byte the strict one. The parameters are
/// therefore used as handed back and never decoded again (a second decode
/// would turn `%2541` into `A`).
///
/// This is the one gate every HTTP entry point (Ipe.Server handlers, every
/// Ipe.Web route, the static file mounts) passes before any handler or file
/// service sees the URI.
pub(crate) fn strict_url(uri: &axum::http::Uri) -> Result<StrictUrl, RequestRejection> {
    let path = crate::encoding::DecodedPath::parse(uri.path())
        .map_err(|_| RequestRejection::BadRequest)?;
    let query = parse_query(uri.query()).map_err(|_| RequestRejection::BadRequest)?;
    Ok(StrictUrl { path, query })
}

/// [`strict_url`], keeping only the decoded query, for an entry point that
/// never matches on the path.
pub(crate) fn strict_url_query(
    uri: &axum::http::Uri,
) -> Result<HashMap<String, String>, RequestRejection> {
    strict_url(uri).map(|url| url.query)
}

/// Middleware answering the fixed 400 `Bad Request` for a malformed request
/// URI before the inner service runs.
pub(crate) async fn refuse_malformed_url(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match strict_url_query(req.uri()) {
        Ok(_) => next.run(req).await,
        Err(rejection) => rejection.status_and_reason().into_response(),
    }
}

/// The listener-wide strict URL gate: no route, mount or fallback of `app`
/// sees a malformed path or query.
///
/// Each entry point also gates itself (`build_request`, the Web router and
/// page handler, `strict_serve_dir`), so this is the independent second
/// boundary.
fn gate_listener(app: axum::Router) -> axum::Router {
    app.layer(axum::middleware::from_fn(refuse_malformed_url))
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
/// malformed one was already answered 400 by [`refuse_malformed_url`]), then
/// parsed into a `RelPath`, so a segment that climbs, re-anchors, names a
/// device or a stream, or aliases another entry under the regime is refused
/// before any join. An empty segment (`/a//b`) names no entry and is refused
/// too. The join itself ([`crate::path::join_rel`]) then re-checks the joined
/// text independently; its result is discarded here.
///
/// # Errors
///
/// The [`StaticRefusal`] of the first boundary that refused the path.
pub(crate) fn static_request(
    uri_path: &str,
    root: &std::path::Path,
    regime: crate::path_core::Regime,
) -> Result<StaticRequest, StaticRefusal> {
    let decoded =
        crate::encoding::DecodedPath::parse(uri_path).map_err(StaticRefusal::Malformed)?;
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

/// A static file service behind the strict URL gate and the static path gate.
///
/// `ServeDir` percent-decodes the path itself; the gates make that decode run
/// only on a path the strict core already accepted and [`static_request`]
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
/// A request path [`static_request`] refuses is answered a bare 404 that never
/// echoes the path, whether or not the entry exists.
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
            let admitted = static_request(req.uri().path(), &root, regime).is_ok();
            async move {
                if admitted {
                    next.run(req).await
                } else {
                    axum::http::StatusCode::NOT_FOUND.into_response()
                }
            }
        },
    );
    tower::Layer::layer(
        &axum::middleware::from_fn(refuse_malformed_url),
        tower::Layer::layer(&static_gate, tower_http::services::ServeDir::new(dir)),
    )
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

/// Build the Ipê `ServerRequest` from the axum request.
///
/// Returns the `RequestRejection` when the request must be turned away before
/// the handler runs: a malformed path, path parameter or query is a
/// `BadRequest`, an oversize body is `PayloadTooLarge`. Rejecting here ensures
/// a handler never sees a lossily decoded URL or a silently-truncated body.
async fn build_request(
    req: axum::extract::Request,
) -> Result<(ServerRequest, Option<axum::extract::ws::WebSocketUpgrade>), RequestRejection> {
    use axum::extract::{FromRequestParts, RawPathParams};
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let query = strict_url_query(&uri)?;
    let mut headers = HashMap::new();
    let mut cookies = HashMap::new();
    // Read from the raw bytes of every `Cookie` header, outside the text gate
    // below, so one pair with a non-ASCII byte drops only itself. The first
    // value of a name wins.
    for (name, value) in request_cookie_jar(req.headers()) {
        cookies.entry(name).or_insert(value);
    }
    for (k, v) in req.headers() {
        if let Ok(s) = v.to_str() {
            // Store under  canonical MIME casing (`content-type` ->
            // `Content-Type`), aligning with  request-header storage and the
            // Ipe.Web path, so `server_header` (which canonicalises its lookup
            // key) matches any caller casing.
            headers.insert(
                crate::http_header::canonical_header(k.as_str()),
                s.to_string(),
            );
        }
    }
    let (mut parts, body) = req.into_parts();
    // `strict_url` has already proved the raw path strict, so the router's
    // single decode of each parameter is the strict decode: used as-is. A
    // router refusal (a parameter it could not decode, or no parameter table at
    // all) is a malformed request, never an empty table.
    let params = RawPathParams::from_request_parts(&mut parts, &())
        .await
        .map_err(|_| RequestRejection::BadRequest)?
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    // remoteAddr: trust the real TCP peer (ConnectInfo) by DEFAULT. Only honour a
    // proxy's X-Forwarded-For / X-Real-IP when `IPE_TRUSTED_PROXY` is set — i.e.
    // the operator declares the app sits behind a trusted proxy that sets those
    // headers. Trusting client-supplied XFF unconditionally let ANY client spoof
    // their IP → rate-limit bypass (the fixed-window limiter keys on remoteAddr)
    // + forged access logs. Security-by-default: spoofable headers are opt-in.
    let peer = parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());
    let trust_proxy = crate::system::read_env_var("IPE_TRUSTED_PROXY")
        .map(|v| !v.is_empty() && v != "0" && v != "false")
        .unwrap_or(false);
    let remote_addr = if trust_proxy {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-forwarded-for"))
            .map(|(_, v)| v.split(',').next().unwrap_or("").trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-real-ip"))
                    .map(|(_, v)| v.clone())
            })
            .or(peer)
            .unwrap_or_default()
    } else {
        peer.unwrap_or_default()
    };
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

fn to_axum_response(r: ServerResponse) -> axum::response::Response {
    to_axum_response_with(r, crate::telemetry::security_headers())
}

/// [`to_axum_response`] over the outcome of reading the security headers.
fn to_axum_response_with(
    r: ServerResponse,
    security: Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // A streaming response carries the sentinel body `stream` registered.
    // Claiming it takes its handler, which runs only once the head is built.
    let pending = match claim_streaming_sentinel(&r.body) {
        ServerStreamClaim::Buffered => None,
        ServerStreamClaim::Stream(pending) => Some(pending),
        // This process's sentinel with no live handler: serving it as a
        // buffered body would send the sentinel nonce to the client.
        ServerStreamClaim::Abandoned => {
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

fn method_router(method: &str, h: ErasedHandler) -> axum::routing::MethodRouter {
    use axum::response::IntoResponse;
    use axum::routing::{any, delete, get, post, put};
    let svc = move |req: axum::extract::Request| {
        let h = h.clone();
        async move {
            let (ipe_req, upgrader) = match build_request(req).await {
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
                            let result = h(ipe_req).await;
                            if let Some(ws_resp) = WS_RESPONSE.with(|c| c.take()) {
                                return ws_resp;
                            }
                            match result {
                                Ok(resp) => to_axum_response(resp),
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
    match method.to_uppercase().as_str() {
        "GET" => get(svc),
        "POST" => post(svc),
        "PUT" => put(svc),
        "DELETE" => delete(svc),
        _ => any(svc),
    }
}

fn strip_trailing_slash(p: &str) -> String {
    // strip_suffix is total — drops the trailing '/' without a raw range slice,
    // keeping a lone "/" intact (filtering out the empty result).
    match p.strip_suffix('/') {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => p.to_string(),
    }
}

/// The documented operator var naming `Ipe.Http.Server`'s listen port.
const SERVER_PORT_ENV: &str = "IPE_SERVER_PORT";

/// Server.listen : Int -> List Route -> Task Error ()  — serves via axum/tokio.
/// Detect an unambiguous endpoint collision in the route set BEFORE the axum
/// router is built. axum (matchit) *panics* on a conflicting insert, and that
/// panic fires inside `server_listen`'s task future — before the
/// `CatchPanicLayer`, which only wraps request-time handler panics — so it would
/// crash the listener rather than surface a typed error (a soundness break).
///
/// This pre-check flags ONLY the always-invalid case that never coexists in
/// axum: two handlers claiming the same path with an overlapping method (`ANY`
/// overlaps every verb). It deliberately does NOT reason about `static` /
/// `mountApp` prefix subtrees — a `nest`ed app coexists with sibling routes
/// (a mount at `/` beside `Server.get "/health"` is valid), so a structural
/// subtree rule would over-reject working programs. Those and any residual
/// matchit ambiguity are caught by the per-insert `catch_unwind` in
/// `server_listen`, which mirrors axum's ACTUAL behaviour and so can never
/// over-reject. Fail closed either way: a conflicting set is refused, never bound.
fn endpoint_conflict(routes: &[ServerRoute]) -> Option<String> {
    // Only plain handlers carry an exact (method, path) that can duplicate.
    let handlers: Vec<(String, &str)> = routes
        .iter()
        .filter(|r| matches!(r.target, RouteTarget::Handler(_)))
        .map(|r| (r.method.to_uppercase(), r.path.as_str()))
        .collect();
    conflict_in(&handlers)
}

/// The pure collision core of [`endpoint_conflict`], over already-extracted
/// `(METHOD, path)` handler entries — split out so the refusal set is
/// unit-testable without constructing live axum handlers.
fn conflict_in(handlers: &[(String, &str)]) -> Option<String> {
    for (idx, (ma, pa)) in handlers.iter().enumerate() {
        for (mb, pb) in handlers.iter().skip(idx + 1) {
            // Same path (trailing-slash-insensitive) with an overlapping method.
            let conflict = pa.trim_end_matches('/') == pb.trim_end_matches('/')
                && (ma == mb || ma == "ANY" || mb == "ANY");
            if conflict {
                return Some(format!(
                    "Server.listen: endpoint `{ma} {pa}` conflicts with `{mb} {pb}` — two \
                     handlers may not claim the same path with an overlapping method; give each \
                     endpoint a distinct path or method"
                ));
            }
        }
    }
    None
}

/// The typed error for the per-insert `catch_unwind` backstop: an axum insert
/// panicked (a matchit route conflict) that the structural pre-check did not
/// model. Fail closed with the offending endpoint named.
fn conflict_at(method: &str, path: &str) -> String {
    format!(
        "Server.listen: endpoint `{method} {path}` conflicts with a route already registered on \
         the server — two endpoints may not claim the same path or a path nested under another; \
         give each endpoint a distinct path"
    )
}

/// An endpoint whose path holds a parameter name outside the runtime's one
/// parameter-name grammar ([`crate::encoding::ParamNames`]).
#[derive(Clone, Debug, PartialEq, Eq)]
struct EndpointParamRefusal {
    method: String,
    path: String,
    refusal: crate::encoding::ParamNameRefusal,
}

impl std::fmt::Display for EndpointParamRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Server.listen: endpoint `{} {}` has a malformed path parameter: {}",
            self.method, self.path, self.refusal
        )
    }
}

/// Admit every parameter name of a router path through
/// [`crate::encoding::ParamNames`].
///
/// The router starts a parameter at the first `:` or `*` of a segment and runs
/// it to the segment's end, so the text after that sigil is the name; a second
/// sigil in the same segment is a non-identifier byte of that name.
///
/// # Errors
///
/// The first [`crate::encoding::ParamNameRefusal`] among the path's parameter
/// names: an empty name, a non-identifier name, or a repeated name.
pub fn path_param_names(path: &str) -> Result<(), crate::encoding::ParamNameRefusal> {
    let mut names = crate::encoding::ParamNames::default();
    path.split('/')
        .filter_map(|seg| seg.split_once([':', '*']).map(|(_, name)| name))
        .try_for_each(|name| names.admit(name).map(drop))
}

/// The first endpoint (declaration order) whose path parameters are refused.
fn endpoint_param_refusal(routes: &[ServerRoute]) -> Option<EndpointParamRefusal> {
    routes.iter().find_map(|r| {
        path_param_names(&r.path)
            .err()
            .map(|refusal| EndpointParamRefusal {
                method: r.method.to_uppercase(),
                path: r.path.clone(),
                refusal,
            })
    })
}

pub fn server_listen<E: From<String> + Send + 'static>(
    port: i64,
    routes: Vec<ServerRoute>,
) -> IpeTask<E, ()> {
    Box::pin(async move {
        // Fail-closed parameter-name gate: an empty, non-identifier or repeated
        // path parameter name would make a captured value ambiguous or
        // unreachable, so the whole route set is refused before any insert.
        if let Some(refusal) = endpoint_param_refusal(&routes) {
            return IpeResult::Err(refusal.to_string().into());
        }
        // Fail-closed endpoint-conflict gate (see `endpoint_conflict`): refuse an
        // overlapping route set with a typed error before any axum insert, so a
        // matchit conflict can never panic the listener task.
        if let Some(msg) = endpoint_conflict(&routes) {
            return IpeResult::Err(msg.into());
        }
        // Bind host obeys the one runtime-config precedence: `IPE_HTTP_BIND`
        // (env) > the app's `Host.bind` setting > the posture fallback
        // (loopback unless production). A present `IPE_HTTP_BIND` that is not
        // an IP address refuses the listener.
        let host = match crate::app_config::resolve_host_bind() {
            Ok(host) => host,
            Err(refusal) => return IpeResult::Err(format!("Server.listen: {refusal}").into()),
        };
        let ceilings = match listen_ceilings() {
            Ok(ceilings) => ceilings,
            Err(refusal) => return IpeResult::Err(format!("Server.listen: {refusal}").into()),
        };
        // The framing policy every response carries is parsed before bind, so
        // a value with no header representation refuses the listener.
        if let Err(refusal) = crate::telemetry::frame_ancestors_config() {
            return IpeResult::Err(format!("Server.listen: {refusal}").into());
        }
        let mut app: axum::Router = axum::Router::new();
        // At most ONE mounted web app per server: the embedded app's cookie /
        // CSRF / asset paths are scoped through the process-wide base path
        // (`IPE_WEB_BASE_PATH`), so a SECOND mount at a different prefix would
        // silently mis-scope the first. Reject the second fail-closed (before
        // bind) rather than serve a subtly broken session/CSRF surface.
        #[cfg(feature = "web")]
        let mut web_mounted = false;
        for r in routes {
            // Kept for the fail-closed conflict message: the arm below moves the
            // target's payload out of `r`, but leaves these scalar fields intact.
            let rmethod = r.method.clone();
            let rpath = r.path.clone();
            // Each axum insert is wrapped so a residual matchit conflict the
            // pre-check did not model becomes a typed error, never an escaped
            // panic (the pre-check catches the definite cases; this is the
            // independent backstop — defence in depth for a soundness invariant).
            match r.target {
                RouteTarget::Static(dir) => {
                    let path = strip_trailing_slash(&rpath);
                    let svc = strict_serve_dir(std::path::PathBuf::from(dir));
                    app = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        app.nest_service(&path, svc)
                    })) {
                        Ok(next) => next,
                        Err(_) => return IpeResult::Err(conflict_at(&rmethod, &rpath).into()),
                    };
                }
                RouteTarget::Handler(h) => {
                    let mr = method_router(&rmethod, h);
                    let path = rpath.clone();
                    app = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                        app.route(&path, mr)
                    })) {
                        Ok(next) => next,
                        Err(_) => return IpeResult::Err(conflict_at(&rmethod, &rpath).into()),
                    };
                }
                // `Server.mountApp`: build the embedded web app's router scoped
                // to the prefix, then nest it under that prefix on this same
                // listener (one port). The builder is taken once; a duplicate
                // (a cloned route) finds `None` and is skipped — inert.
                #[cfg(feature = "web")]
                RouteTarget::MountWeb(cell) => {
                    if web_mounted {
                        return IpeResult::Err(
                            "Server.mountApp: at most one Web app may be mounted per server \
                             (the embedded app's cookie/CSRF/asset paths are scoped through one \
                             process-wide base path); mount a single Web app, or serve additional \
                             apps as separate servers"
                                .to_string()
                                .into(),
                        );
                    }
                    let builder = cell
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(build) = builder {
                        let prefix = strip_trailing_slash(&rpath);
                        let sub = build(prefix.clone()).await;
                        app = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            move || app.nest(&prefix, sub),
                        )) {
                            Ok(next) => next,
                            Err(_) => return IpeResult::Err(conflict_at(&rmethod, &rpath).into()),
                        };
                        web_mounted = true;
                    }
                }
            }
        }
        let app = gate_listener(app);
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
        // program passed to `Server.listen`. A malformed env layer falls through,
        // never to `0`.
        let resolved = crate::system::listen_port_from_env(
            (
                SERVER_PORT_ENV,
                crate::system::read_env_var(SERVER_PORT_ENV).ok(),
            ),
            port,
        );
        let port = resolved.port;
        let Ok(port) = u16::try_from(port) else {
            return IpeResult::Err(format!("Server.listen: port {port} is not a TCP port").into());
        };
        // Recorded before the bind, so no dev surface outlives an exposed listener.
        crate::telemetry::record_bind(host);
        let addr = std::net::SocketAddr::new(host, port);
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return IpeResult::Err(resolved.addr_in_use_message().into());
            }
            Err(e) => return IpeResult::Err(format!("Server.listen: bind {}: {}", addr, e).into()),
        };
        crate::system::emit_runtime_log("http.server", &format!("listening on http://{addr}"));
        // with_connect_info so each request carries the peer SocketAddr —
        // populates ServerRequest.remoteAddr (also used by per-IP rate limiting).
        let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
        match axum::serve(listener, svc).await {
            Ok(()) => ok_res(()),
            Err(e) => IpeResult::Err(format!("Server.listen: serve: {}", e).into()),
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

async fn ws_loop<E: From<String> + Send + 'static>(
    mut socket: axum::extract::ws::WebSocket,
    cfg: WsServerCfg<E>,
    id: i64,
    ceilings: WsCeilings,
) {
    use axum::extract::ws::Message;
    use std::time::Duration;
    let max_bytes: usize = ws_max_message_bytes(cfg.maxMessageBytes);
    // Framing-layer enforcement lives on the `WebSocketUpgrade` builder, applied
    // at upgrade time in `server_web_socket_upgrade` (`.max_message_size()` /
    // `.max_frame_size()` — axum 0.7.9 exposes both). A frame over the cap is
    // rejected by tokio-tungstenite before it reaches this loop. The Text/Binary
    // size checks below are application-layer defense in depth (belt-and-braces
    // against a future axum/tungstenite version silently dropping the cap).
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
        let _ = socket.send(Message::Close(None)).await;
        return;
    }
    let _ = (cfg.onConnect)(WsHandle::WebSocketServer(id)).await;
    // Heartbeat: send a Ping every `ceilings.heartbeat_secs` seconds to keep the
    // connection alive through proxies and detect silent drops.  Mirrors
    // `wsDefaultPingInterval = 30s` + `wsPingTimeout = 10s` pattern in
    // ``.  axum auto-replies to incoming Pong
    // frames on our behalf, so we only need to send the Ping here.
    let mut heartbeat = tokio::time::interval(Duration::from_secs(ceilings.heartbeat_secs));
    heartbeat.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Text(t))) => {
                    if t.len() > max_bytes {
                        let _ = socket.send(Message::Close(None)).await;
                        break;
                    }
                    let _ = (cfg.onMessage)(WsHandle::WebSocketServer(id), t).await;
                }
                Some(Ok(Message::Binary(b))) => {
                    if b.len() > max_bytes {
                        let _ = socket.send(Message::Close(None)).await;
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
                    let _ = (cfg.onMessage)(WsHandle::WebSocketServer(id), s).await;
                }
                Some(Ok(Message::Close(_))) | None => break,
                // Incoming Ping/Pong frames are auto-handled by axum; no user
                // callback needed.
                Some(Ok(_)) => {}
                Some(Err(e)) => {
                    let _ = (cfg.onError)(WsHandle::WebSocketServer(id), format!("ws read error: {}", e).into()).await;
                    break;
                }
            },
            outgoing = rx.recv() => match outgoing {
                Some(WsOut::Text(s)) => { if socket.send(Message::Text(s)).await.is_err() { break; } }
                Some(WsOut::Binary(b)) => { if socket.send(Message::Binary(b)).await.is_err() { break; } }
                Some(WsOut::Close) => { let _ = socket.send(Message::Close(None)).await; break; }
                None => break,
            },
            _ = heartbeat.tick() => {
                // Send a Ping frame; if the peer has gone away the send will
                // fail and we break, triggering onClose cleanup.
                if socket.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            },
        }
    }
    let _ = (cfg.onClose)(WsHandle::WebSocketServer(id)).await;
    ws_registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
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
                let resp = up.on_upgrade(move |socket| ws_loop(socket, cfg, id, ceilings));
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

    /// Zero is rejected and the default is used.
    #[test]
    fn ws_heartbeat_zero_falls_back_to_default() {
        let result: u64 = Some("0".to_string())
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        assert_eq!(result, 30);
    }

    /// Non-numeric input is rejected and the default is used.
    #[test]
    fn ws_heartbeat_non_numeric_falls_back_to_default() {
        let result: u64 = Some("not-a-number".to_string())
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(30);
        assert_eq!(result, 30);
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

/// Tags `resp` with the allowed origin `allow`, replacing any
/// `Access-Control-Allow-Origin` the handler set in any case. A specific
/// origin (not `*`) makes the response origin-dependent, so `Origin` joins the
/// handler's `Vary` (merged in any case, never clobbered) and a shared cache
/// cannot serve one origin's grant to another.
fn tag_cors(resp: &mut ServerResponse, allow: Option<String>) {
    let Some(a) = allow else {
        return;
    };
    if a != "*" {
        let vary = match header_values_ci(&resp.headers, "Vary") {
            Some(prev)
                if prev
                    .split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("origin")) =>
            {
                prev
            }
            Some(prev) => format!("{prev}, Origin"),
            None => "Origin".to_owned(),
        };
        set_header_replacing(&mut resp.headers, "Vary".to_owned(), vary);
    }
    set_header_replacing(
        &mut resp.headers,
        "access-control-allow-origin".to_owned(),
        a,
    );
}

/// Middleware.withCors : List String -> Handler -> Handler. Echoes an allowed
/// Origin (or `*`), answers preflight OPTIONS with 204, and tags responses.
pub fn middleware_with_cors<E, H>(origins: Vec<String>, h: H) -> ServerHandler<E>
where
    E: Send + 'static,
    H: IntoServerHandler<E>,
{
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        let req_origin = header_ci(&req.headers, "origin").unwrap_or("").to_string();
        let allow = if origins.iter().any(|o| o == "*") {
            Some("*".to_string())
        } else if origins.iter().any(|o| o == &req_origin) && !req_origin.is_empty() {
            Some(req_origin)
        } else {
            None
        };
        if req.method.eq_ignore_ascii_case("OPTIONS") {
            let mut resp = plain_resp(
                204,
                "",
                &[
                    (
                        "access-control-allow-methods",
                        "GET, POST, PUT, DELETE, OPTIONS",
                    ),
                    (
                        "access-control-allow-headers",
                        "Content-Type, Authorization",
                    ),
                ],
            );
            tag_cors(&mut resp, allow);
            return Box::pin(async move { ok_res(resp) });
        }
        let task = h(req);
        Box::pin(async move {
            match task.await {
                IpeResult::Ok(mut resp) => {
                    tag_cors(&mut resp, allow);
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

/// 64 lowercase-hex chars (two concatenated UUIDv4s, ~244 combined random
/// bits — comfortably above the 128-bit CSRF-token floor). `uuid::Uuid::new_v4`
/// draws from the OS CSPRNG, the approved security-bearing-randomness source
/// per `random.rs`. Re-exported from `web/csrf.rs` as `gen_token`.
pub fn csrf_gen_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
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
    let h = h.into_server_handler();
    Arc::new(move |req: ServerRequest| {
        let safe = matches!(
            req.method.to_ascii_uppercase().as_str(),
            "GET" | "HEAD" | "OPTIONS"
        );
        let cookie_name = csrf_cookie_name();
        let existing = req.cookies.get(cookie_name.text()).cloned();
        let token = existing
            .clone()
            .filter(|t| csrf_token_well_formed(t))
            .unwrap_or_else(csrf_gen_token);
        if !safe {
            let cookie_tok = existing.unwrap_or_default();
            let header_tok = header_ci(&req.headers, "x-csrf-token")
                .unwrap_or("")
                .to_string();
            if !csrf_pair_valid(&cookie_tok, &header_tok) {
                return Box::pin(async move {
                    ok_res(plain_resp(403, "csrf token invalid or missing", &[]))
                });
            }
        }
        // Capture the request-scoped TLS signal HERE — before `req` is moved
        // into `h(req)` below. `ServerRequest` is not `Clone`-cheap-by-design
        // (it owns the full body/headers/cookies maps) and the wrapped
        // handler legitimately needs to consume it, so there is no request
        // left to inspect once `task` is awaited. `bool` is `Copy`, so this
        // one-line snapshot is the entire adaptation needed versus the
        // session-cookie fix (which reads `headers` at cookie-set time
        // because `page_response` runs BEFORE the request is handed off).
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
mod tests {
    use super::*;
    use std::future::ready;

    /// `Ipe.Http.Server` resolves through the shared resolver under its own
    /// operator var: an operator value wins over the source port, and a
    /// supervisor relocation wins over both.
    #[test]
    fn ipe_server_port_resolves_operator_over_source_under_relocation() {
        let resolve = |relocation: Option<&str>, operator: Option<&str>| {
            crate::system::resolve_listen_port(
                relocation.map(str::to_owned),
                (SERVER_PORT_ENV, operator.map(str::to_owned)),
                8000,
            )
        };
        assert_eq!(resolve(None, Some("9123")).port, 9123);
        assert_eq!(resolve(Some("9100"), Some("9123")).port, 9100);
        assert_eq!(resolve(None, Some("0")).port, 8000);
        assert!(
            resolve(None, None)
                .addr_in_use_message()
                .contains("IPE_SERVER_PORT=8123 ipe dev run")
        );
        assert!(
            !resolve(Some("9100"), None)
                .addr_in_use_message()
                .contains("IPE_SERVER_PORT")
        );
    }

    #[test]
    fn distinct_handlers_never_conflict() {
        // Happy path: sibling handlers and different verbs on one path coexist —
        // the pre-check must not over-reject.
        let ok = [
            ("GET".to_string(), "/api/users"),
            ("GET".to_string(), "/api/posts"),
            ("POST".to_string(), "/api/users"), // same path, different verb
            ("DELETE".to_string(), "/api/users/:id"),
        ];
        assert!(conflict_in(&ok).is_none());
    }

    #[test]
    fn duplicate_method_and_path_is_refused() {
        // Prove the refusal: the same endpoint twice (trailing slash is the same
        // endpoint) is turned back before any axum insert.
        let dup = [("GET".to_string(), "/api"), ("GET".to_string(), "/api/")];
        assert!(conflict_in(&dup).is_some());
    }

    #[test]
    fn any_verb_overlaps_every_method() {
        // `ANY` claims every verb, so it collides with a specific-verb handler on
        // the same path — axum would panic on the overlapping method route.
        let any = [("ANY".to_string(), "/hook"), ("POST".to_string(), "/hook")];
        assert!(conflict_in(&any).is_some());
    }

    #[test]
    fn identifier_path_params_are_admitted() {
        for ok in [
            "/",
            "/api/users",
            "/api/users/:id",
            "/raw/*rest",
            "/a/:x/b/:_y",
            "/a/:a_Z9/:Z",
            "/a/:x/*y",
            "/v-:id",
        ] {
            assert_eq!(path_param_names(ok), Ok(()), "{ok}");
        }
    }

    /// Prove the refusals: every name outside `[A-Za-z_][A-Za-z0-9_]*`, and
    /// every repeat, is refused with its typed cause.
    #[test]
    fn malformed_path_params_are_refused() {
        use crate::encoding::ParamNameRefusal as R;
        assert_eq!(path_param_names("/:"), Err(R::Empty));
        assert_eq!(path_param_names("/files/*"), Err(R::Empty));
        for (bad, at) in [
            ("/:1a", 0),
            ("/:9", 0),
            ("/:\u{e9}", 0),
            ("/:a-b", 1),
            ("/:a:b", 1),
            ("/:a*b", 1),
            ("/:a_Z9-", 4),
            ("/:id.json", 2),
        ] {
            let refused = path_param_names(bad);
            assert!(
                matches!(refused, Err(R::NotIdentifier { at: off }) if off.get() == at),
                "{bad} must break at byte {at}, got {refused:?}"
            );
        }
        for dup in ["/:id/:id", "/:id/*id", "/x/:a/y/:a"] {
            assert!(
                matches!(path_param_names(dup), Err(R::Duplicate { .. })),
                "{dup} must be refused as a repeat"
            );
        }
    }

    /// The listener refuses a route set with a malformed parameter name
    /// before any insert or bind, naming the endpoint and the cause.
    #[tokio::test]
    async fn listen_refuses_a_malformed_path_param_before_bind() {
        let routes = vec![
            server_static("/ok".to_string(), "dir".to_string()),
            server_static("/:id/:id".to_string(), "dir".to_string()),
        ];
        let refusal = endpoint_param_refusal(&routes);
        assert_eq!(refusal.as_ref().map(|r| r.path.as_str()), Some("/:id/:id"));
        // A listener that got past the refusal would bind and serve forever;
        // the timeout turns that regression into a failure instead of a hang.
        let listened: IpeResult<String, ()> =
            tokio::time::timeout(std::time::Duration::from_secs(10), server_listen(0, routes))
                .await
                .expect("a refused route set must return before binding, not serve");
        assert!(
            matches!(listened, IpeResult::Err(_)),
            "a malformed parameter name must refuse the listener"
        );
        let IpeResult::Err(msg) = listened else {
            panic!("a malformed parameter name must refuse the listener");
        };
        assert!(
            msg.contains("endpoint `GET /:id/:id` has a malformed path parameter")
                && msg.contains("parameter `id` appears twice"),
            "{msg}"
        );
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
        let listened: IpeResult<String, ()> = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server_listen(0, Vec::new()),
        )
        .await
        .expect("a refused framing policy must return before binding, not serve");
        let IpeResult::Err(msg) = listened else {
            panic!("a `;` in IPE_WEB_FRAME_ANCESTORS must refuse the listener");
        };
        assert!(
            msg.starts_with("Server.listen: IPE_WEB_FRAME_ANCESTORS holds `;`"),
            "{msg}"
        );
        println!("\n{}", crate::telemetry::frame_ancestors_child::REFUSED);
    }

    /// A present `IPE_HTTP_BIND` that is not an IP address refuses the listener
    /// before it binds.
    #[tokio::test]
    async fn listen_refuses_a_bind_that_is_not_an_ip_address() {
        for raw in ["localhost", "127.0.0.1:8080", "[::1]", " 127.0.0.1"] {
            crate::system::locked_set_var("IPE_HTTP_BIND", raw);
            // A listener that got past the refusal would bind and serve forever;
            // the timeout turns that regression into a failure instead of a hang.
            let listened: Result<IpeResult<String, ()>, _> = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                server_listen(0, Vec::new()),
            )
            .await;
            crate::system::locked_remove_var("IPE_HTTP_BIND");
            let refused = matches!(&listened, Ok(IpeResult::Err(msg))
                if msg.starts_with("Server.listen: IPE_HTTP_BIND must be an IP address"));
            assert!(refused, "IPE_HTTP_BIND={raw:?} must refuse the listener");
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

    /// Run `build_request` inside a router matched on `pattern`.
    ///
    /// Returns what `build_request` produced for `wire`, or `None` when the
    /// router never reached the handler (no route matched).
    async fn routed_build(
        pattern: &str,
        wire: axum::http::Request<axum::body::Body>,
    ) -> Option<Result<ServerRequest, RequestRejection>> {
        use tower::ServiceExt;
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen = std::sync::Arc::clone(&slot);
        let app = axum::Router::new().route(
            pattern,
            axum::routing::any(move |req: axum::extract::Request| {
                let seen = std::sync::Arc::clone(&seen);
                async move {
                    let built = build_request(req).await.map(|(r, _)| r);
                    if let Ok(mut s) = seen.lock() {
                        *s = Some(built);
                    }
                    ""
                }
            }),
        );
        let _ = app.oneshot(wire).await;
        slot.lock().ok().and_then(|mut s| s.take())
    }

    #[tokio::test]
    async fn build_request_without_router_params_is_bad_request() {
        // Prove the refusal: a request that never passed the router carries no
        // parameter table, and that is a malformed request, never an empty one.
        let wire = axum::http::Request::builder()
            .method("GET")
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("test request builds");
        assert!(matches!(
            build_request(wire).await,
            Err(RequestRejection::BadRequest)
        ));
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
    }

    /// Serve `uri` through a real `method_router` routed on `/u/:id`.
    ///
    /// The handler answers `"{id}|{q}"` from its path parameter and query, and
    /// counts its runs. Returns the status, the body and the run count.
    async fn serve_counted(uri: &str) -> (axum::http::StatusCode, String, usize) {
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
        let app = axum::Router::new().route("/u/:id", method_router("GET", handler));
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
        let app = axum::Router::new()
            .nest_service("/static", strict_serve_dir_with(dir.to_path_buf(), regime));
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

    /// Serve `uri` through `gate_listener` over a raw axum route and fallback
    /// that do no URL check of their own. Returns the status, the body and how
    /// many times either inner handler ran.
    async fn serve_gated(uri: &str) -> (axum::http::StatusCode, String, usize) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::ServiceExt;
        let runs = Arc::new(AtomicUsize::new(0));
        let on_route = Arc::clone(&runs);
        let on_fallback = Arc::clone(&runs);
        let inner = axum::Router::new()
            .route(
                "/raw/*rest",
                axum::routing::get(move || async move {
                    on_route.fetch_add(1, Ordering::SeqCst);
                    "route"
                }),
            )
            .fallback(move || async move {
                on_fallback.fetch_add(1, Ordering::SeqCst);
                "fallback"
            });
        let app = gate_listener(inner);
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
        (status, body, runs.load(Ordering::SeqCst))
    }

    #[tokio::test]
    async fn listener_gate_refuses_a_malformed_url_before_any_route_or_fallback() {
        // Prove the refusals of the listener-wide layer on its own: the inner
        // route and fallback carry no URL check, so only the layer stands
        // between them and a malformed path or query.
        for uri in [
            "/raw/%zz",
            "/raw/a%C3/%A9",
            "/raw/x?q=%zz",
            "/elsewhere/%C0%AF",
            "/elsewhere?%C3=1",
        ] {
            let (status, body, runs) = serve_gated(uri).await;
            assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{uri:?}");
            assert_eq!(body, "Bad Request", "{uri:?} must not echo the request");
            assert_eq!(runs, 0, "{uri:?} must never reach a route or fallback");
        }
        for (uri, want) in [
            ("/raw/a%20b", "route"),
            ("/raw/a%2Fb?q=a+b", "route"),
            ("/elsewhere", "fallback"),
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
        let out = axum_body_string(to_axum_response(ipe)).await;
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
        let out = axum_body_string(to_axum_response(server_html(html.to_string()))).await;
        crate::system::locked_remove_var("ENV");
        assert_eq!(out, html, "release HTML must be verbatim");
    }

    #[tokio::test]
    async fn to_axum_response_leaves_non_html_untouched() {
        // JSON / plain-text responses never get the banner (only text/html).
        let ipe = server_json(r#"{"ok":true}"#.to_string());
        let out = axum_body_string(to_axum_response(ipe)).await;
        assert_eq!(out, r#"{"ok":true}"#, "non-html body must be verbatim");

        let ipe_text = server_text("plain body</body>".to_string());
        let out_text = axum_body_string(to_axum_response(ipe_text)).await;
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
        let resp = to_axum_response(r);
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
        to_axum_response(r)
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
        let resp = to_axum_response(r);
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
            Err(crate::telemetry::FrameAncestorsRefusal::Blank),
        );
        assert_eq!(
            refused.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(refused.headers().get("x-frame-options").is_none());
        let framed = to_axum_response_with(
            server_text("ok".to_owned()),
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
        let resp = to_axum_response(r);
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
            let resp = to_axum_response(r);
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
        let resp = to_axum_response(r);
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(axum::http::header::SET_COOKIE).is_none());
        assert!(resp.headers().get("x-injected").is_none());
    }

    /// A `stream` response whose handler emits nothing.
    async fn streamed(content_type: &str) -> ServerResponse {
        let task = server_stream_stream::<IpeError, _>(content_type.to_owned(), |_w| {
            Box::pin(async { IpeResult::Ok(()) }) as IpeTask<IpeError, ()>
        });
        let built = match task.await {
            IpeResult::Ok(r) => Some(r),
            IpeResult::Err(_) => None,
        };
        built.expect("`stream` must build a response")
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
        let mut r = streamed("text/event-stream").await;
        r.headers
            .insert("Cache-Control".to_owned(), "no-store".to_owned());
        let resp = to_axum_response_with(r, framed_security());
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
        let mut r = streamed("text/event-stream").await;
        r = server_with_cookie(cookie("a", "1"), r);
        r = server_with_cookie(cookie("b", "2"), r);
        let resp = to_axum_response_with(r, framed_security());
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
        let r = streamed("text/event-stream").await;
        let resp = to_axum_response_with(r, Err(crate::telemetry::FrameAncestorsRefusal::Blank));
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
            let mut r = streamed("text/event-stream").await;
            r.headers.insert(name.to_owned(), value.to_owned());
            let resp = to_axum_response_with(r, framed_security());
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
            let resp = to_axum_response_with(buffered, framed_security());
            assert_eq!(
                resp.status(),
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "{first:?}/{second:?}"
            );
            let mut r = streamed("text/event-stream").await;
            r.headers.insert(first.to_owned(), first_value.to_owned());
            r.headers.insert(second.to_owned(), second_value.to_owned());
            let resp = to_axum_response_with(r, framed_security());
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
        let resp = to_axum_response_with(r, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
        assert_eq!(single_header(&resp, "location"), Some("/b"));
        assert_eq!(single_header(&resp, "x-custom"), Some("2"));
    }

    /// The response `middleware_with_cors` allowing `origins` makes of a GET
    /// from `https://a.example` whose handler set `headers`, as it is sent.
    async fn cors_tagged(origins: &[&str], headers: &[(&str, &str)]) -> axum::response::Response {
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
        let mut req_headers = HashMap::new();
        req_headers.insert("Origin".to_owned(), "https://a.example".to_owned());
        let IpeResult::Ok(r) = h(mk_req("GET", HashMap::new(), req_headers)).await else {
            panic!("the CORS middleware must pass the handler's response through");
        };
        to_axum_response_with(r, framed_security())
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
                let resp = cors_tagged(origins, &[(name, "https://evil.example")]).await;
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
        for name in ["Vary", "VARY", "vary"] {
            let resp = cors_tagged(&["https://a.example"], &[(name, "Accept-Encoding")]).await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{name}");
            assert_eq!(
                single_header(&resp, "vary"),
                Some("Accept-Encoding, Origin"),
                "{name}"
            );
            let resp = cors_tagged(&["https://a.example"], &[(name, "origin")]).await;
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{name}");
            assert_eq!(single_header(&resp, "vary"), Some("origin"), "{name}");
        }
        let resp = cors_tagged(&["https://a.example"], &[]).await;
        assert_eq!(single_header(&resp, "vary"), Some("Origin"));
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
        let resp = to_axum_response_with(buffered, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        let resp = to_axum_response_with(streamed("text/\u{e9}").await, framed_security());
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
        let r = built(stream_with_flag(refused_ran.clone()).await);
        let resp = to_axum_response_with(r, Err(crate::telemetry::FrameAncestorsRefusal::Blank));
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(!refused_ran.load(std::sync::atomic::Ordering::SeqCst));
        let served_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = built(stream_with_flag(served_ran.clone()).await);
        let resp = to_axum_response_with(r, framed_security());
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        for _ in 0..1024 {
            if served_ran.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(served_ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    /// A stream sentinel served a second time has no live handler: it answers
    /// 500, never a buffered body that sends the sentinel nonce.
    #[tokio::test]
    async fn abandoned_stream_sentinel_answers_500_without_the_sentinel() {
        let r = streamed("text/event-stream").await;
        let again = r.clone();
        let first = to_axum_response_with(r, framed_security());
        assert_eq!(first.status(), axum::http::StatusCode::OK);
        let second = to_axum_response_with(again, framed_security());
        assert_eq!(
            second.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        let body = axum_body_string(second).await;
        assert!(!body.contains("__ipe_stream:"), "{body:?}");
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
            let resp = to_axum_response(server_redirect(raw.to_owned()));
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
            h(req).await.expect("guarded handler never returns Err")
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
    }
}

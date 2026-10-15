//! Ipe.Web CSRF protection + security response headers.
//!
//! Double-submit cookie CSRF protection + security response headers.
//!
//!   - The `__ipe_csrf` cookie is `SameSite=Strict` + `Secure` (in production /
//!     frame-ancestors mode) — SameSite=Strict is itself a strong CSRF defense,
//!     the double-submit token is belt-and-suspenders.
//!   - An `Origin` same-origin check against the request's authority, on by
//!     default (`IPE_WEB_CSRF_ORIGIN_CHECK=off` behind a proxy that rewrites
//!     `Host`): a request with an `Origin` but no authority is refused.
//!   - `X-Content-Type-Options: nosniff` + a restrictive `Permissions-Policy`.
//!
//! The Ipe.Web client POSTs JSON to `/_ipe/event` with an `X-Ipe-Csrf` header
//! (never a form body), so the middleware validates header-vs-cookie WITHOUT
//! reading the request body — no buffering, no body-consumption hazard.

use crate::env_grammar::EnvFlag;
use crate::env_registry::security::WEB_CSRF_ORIGIN_CHECK;
use crate::telemetry;
use axum::http::{HeaderMap, StatusCode, request::Parts};
use axum::response::{IntoResponse, Response};

/// Per-app CSRF cookie name derived from the sub-app base path.
///
/// When cookies are Secure (production / TLS /
/// frame-ancestors), use the `__Host-` prefix — the browser then refuses any
/// `Set-Cookie` carrying a `Domain=` attribute, which blocks the
/// sibling-subdomain cookie-fixation vector. `__Host-` MANDATES
/// `Secure + Path=/ + no-Domain`, and these properties are preserved for every
/// app — the per-app identity is encoded in the cookie name suffix, not the
/// path. Plain-HTTP dev falls back to the bare name (SameSite=Strict is still
/// the primary guard).
///
/// The app identity suffix is derived from `base` (the normalised
/// `IPE_WEB_BASE_PATH` for this process) using the same alphanumeric-or-`_`
/// transform the session cookie uses (`web::cookie_name_for`). Root apps
/// (`base` is empty) get no suffix. Sub-apps get a suffix that exactly mirrors
/// their session cookie's suffix, keeping CSRF and session identities in sync.
///
/// Both SET and READ paths must call this with the same `base` for a given app,
/// so a token minted by app A validates only against app A's cookie — a token
/// set by the host app cannot satisfy a sub-app's validator, and vice-versa.
pub fn csrf_cookie_name_for(base: &str) -> crate::server::CookieName {
    use crate::server::{CookieName, RuntimeCookie};
    let prefix = if cookies_secure() {
        RuntimeCookie::HostCsrf
    } else {
        RuntimeCookie::WebCsrf
    };
    let suffix: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    CookieName::runtime(prefix, &suffix)
}

/// The header the client echoes the CSRF token in (`X-Ipê-Csrf`).
pub const CSRF_HEADER: &str = "x-ipe-csrf";

/// Whether CSRF protection is on, under the one config precedence with a
/// stricter-only floor for the in-code setting. CSRF is ON by default;
/// `IPE_CSRF=off|0|false` (the operator env override, top of precedence)
/// disables it; a `Web.csrf` setting may only ENFORCE it, never disable it (a
/// setting cannot lower the posture below the fail-closed default). The decision
/// is snapshotted once into a `OnceLock` on first call (env + installed settings
/// are both stable at process start; same rationale as `cookies_secure()` —
/// eliminates a per-request `getenv` + global env-lock acquisition on every
/// mutating request).
pub fn csrf_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        let env_enabled = !matches!(
            crate::system::read_env_var("IPE_CSRF").ok().as_deref(),
            Some("off") | Some("0") | Some("false")
        );
        // Built-in default is on (fail-closed); a setting can only strengthen.
        crate::app_config::resolve_csrf_enabled(env_enabled, true)
    })
}

pub use crate::telemetry::frame_ancestors;

/// The security headers of the `Ipe.Web` page response serving `page`: its
/// policy admits the nonce `page`'s markup was stamped with.
///
/// # Errors
///
/// The [`crate::telemetry::FrameAncestorsRefusal`] of a refused
/// `IPE_WEB_FRAME_ANCESTORS`: the page answers `500`.
pub fn security_headers(
    page: &crate::html::StampedHtml,
) -> Result<Vec<(&'static str, String)>, crate::telemetry::FrameAncestorsRefusal> {
    crate::telemetry::security_headers(&crate::csp::Guarded::WebPage {
        style_nonce: page.nonce().clone(),
    })
}

/// Whether to mark cookies `Secure`: [`cookies_secure_with`] over the process.
///
/// Snapshotted once into a `OnceLock` on first call (env is stable at process
/// start; eliminates per-request `getenv` + the TOCTOU race between
/// `cookies_secure()` deciding on `__Host-` and `csrf_set_cookie()` writing it).
pub fn cookies_secure() -> bool {
    use std::sync::OnceLock;
    static SECURE: OnceLock<bool> = OnceLock::new();
    *SECURE.get_or_init(|| {
        cookies_secure_with(
            telemetry::dev_intent_from_env().as_ref(),
            frame_ancestors().is_some(),
        )
    })
}

/// Whether cookies are `Secure` under an explicit dev-intent proof.
///
/// `Secure` unless `dev` holds; frame-ancestors mode (always HTTPS) is
/// `Secure` even then. Every release build is therefore `Secure`.
#[must_use]
pub const fn cookies_secure_with(dev: Option<&telemetry::DevIntent>, framed: bool) -> bool {
    dev.is_none() || framed
}

/// ~244 random bits (two concatenated UUIDv4s) as 64 lowercase-hex chars —
/// comfortably above the 128-bit CSRF-token floor. Single definition shared with
/// `server.rs`; re-exported here under the `gen_token` name the `web` surface uses.
#[cfg(feature = "web")]
pub use crate::server::csrf_gen_token as gen_token;

/// A token "looks valid" if it is the expected 64 lowercase-hex shape — used to
/// decide whether to reuse the browser's existing cookie token vs mint a fresh
/// one (a malformed/forged cookie value is replaced, never trusted). Single
/// definition shared with `server.rs`; re-exported here under the
/// `token_is_well_formed` name the `web` surface uses.
#[cfg(feature = "web")]
pub use crate::server::csrf_token_well_formed as token_is_well_formed;

/// Returns `true` iff BOTH tokens are well-formed AND compare equal in constant
/// time. The structural gate runs before the secret compare — that ordering does
/// not reveal the secret value because well-formedness checks only length and
/// character class. Fail-closed: any malformed, missing, or mismatched pair
/// returns `false`. Delegates to the shared `server::csrf_pair_valid`.
#[cfg(feature = "web")]
pub use crate::server::csrf_pair_valid;

/// The decoded value of the request cookie `name` (generic; the session
/// cookie has its own base-path-aware reader in `mod.rs`).
///
/// Names compare whole, so a cookie named `ipe_csrf` never matches
/// `__Host-ipe_csrf` or the reverse.
pub fn cookie_value(headers: &HeaderMap, name: &crate::server::CookieName) -> Option<String> {
    crate::server::request_cookie(headers, name)
}

/// Build the `Set-Cookie` value for the CSRF cookie.
///
/// `base` is the normalised `IPE_WEB_BASE_PATH` for this app — threaded from
/// `web_base_path()` by the caller so the cookie name is per-app.
///
/// `HttpOnly`: the client reads the token from the injected page JS, not from
/// the cookie directly, so `HttpOnly` is safe and blocks token theft via XSS.
/// `SameSite=Strict` normally; `SameSite=None; Secure` in frame-ancestors mode.
/// `Path=/` is always `/` — the `__Host-` prefix mandates it, and keeping it
/// constant means the browser sends the cookie on every request regardless of
/// sub-path, so the double-submit validate path always sees it.
pub fn csrf_set_cookie(token: &str, base: &str) -> crate::server::SetCookie {
    use crate::server::{CookieAttributes, CookiePath, CookieValue, SameSite, SetCookie};
    // Cross-site iframe: the cookie must cross sites -> `SameSite=None`, which
    // always renders `Secure`. Production / TLS: the `__Host-` name makes
    // `Secure` mandatory. Plain-HTTP dev: bare name, no `Secure` (a browser
    // drops a `Secure` cookie on `http://`).
    let same_site = if frame_ancestors().is_some() {
        SameSite::None
    } else {
        SameSite::Strict
    };
    SetCookie::new(
        &csrf_cookie_name_for(base),
        &CookieValue::encode(token),
        CookieAttributes {
            path: CookiePath::root(),
            http_only: true,
            same_site,
            secure: cookies_secure(),
            max_age_secs: None,
        },
    )
}

/// Paths exempt from CSRF validation (observability paths, console prefix,
/// SSE). GET/HEAD/OPTIONS are exempt by method, separately.
///
/// The `/_ipe/hot-*` family (`hot-appearance`, `hot-transition`, `hot-msg`,
/// `hot-subs`, `hot-init`, `hot-wiring`) is exempt because these are not
/// browser-driven POSTs: each is a server-to-server call from the `ipe dev watch`
/// process, authenticated by its own per-process `X-Ipe-Hot-Token` (a stronger
/// control here than the browser-oriented CSRF cookie, which the watch does not
/// hold). All these routes are mounted only under the dev overlay gate, so they do
/// not exist at all in a production build — there is nothing to exempt there.
pub fn is_exempt_path(path: &str) -> bool {
    matches!(
        path,
        "/_ipe/healthz"
            | "/_ipe/readyz"
            | "/_ipe/metrics"
            | "/_ipe/buildinfo"
            | "/_ipe/sse"
            | "/_ipe/observability/ingest"
            | "/_ipe/hot-appearance"
            | "/_ipe/hot-transition"
            | "/_ipe/hot-msg"
            | "/_ipe/hot-subs"
            | "/_ipe/hot-init"
            | "/_ipe/hot-wiring"
    ) || path == "/_ipe/console"
        || path.starts_with("/_ipe/console/")
}

/// The authority a request was addressed to, as the app listener's Host
/// admission parses it: the target URI's (absolute-form, HTTP/2 `:authority`),
/// else the one `Host` header.
///
/// Never empty and never ambiguous, so a comparison against it can never pass
/// vacuously or against one of two disagreeing authorities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestAuthority<'a>(&'a str);

impl<'a> RequestAuthority<'a> {
    /// The authority `parts` names, or `None` when
    /// [`crate::inbound_authority::Authority::from_request`] refuses it: no
    /// authority, two `Host` headers, a `Host` disagreeing with the target URI,
    /// or a malformed one.
    #[must_use]
    pub fn of(parts: &'a Parts) -> Option<Self> {
        if crate::inbound_authority::Authority::from_request(parts).is_err() {
            return None;
        }
        parts
            .uri
            .authority()
            .map(axum::http::uri::Authority::as_str)
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::HOST)
                    .and_then(|host| host.to_str().ok())
            })
            .map(Self)
    }

    /// The authority text.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.0
    }
}

/// The origin-check switch, read once per process.
///
/// A refused value reads as `On`: the startup check has already refused the
/// start, and a check that cannot read its switch stays closed.
fn origin_check() -> EnvFlag {
    use std::sync::OnceLock;
    static CHECK: OnceLock<EnvFlag> = OnceLock::new();
    *CHECK.get_or_init(|| WEB_CSRF_ORIGIN_CHECK.read().unwrap_or(EnvFlag::On))
}

/// Fixes the origin-check switch at startup, so a later `System.setenv` cannot move it.
pub fn fix_origin_check() {
    origin_check();
}

/// Whether the `Origin` check refuses a request under the switch `check`.
///
/// Not applied while `framed` (cross-origin embedding is intentional there) or
/// when the request carries no `Origin`, where the CSRF token stays the gate. A
/// second `Origin`, one that is not visible ASCII, or one on a request naming no
/// single well-formed authority is refused.
fn origin_mismatch(check: EnvFlag, framed: bool, parts: &Parts) -> bool {
    if matches!(check, EnvFlag::Off) || framed {
        return false;
    }
    let mut origins = parts.headers.get_all(axum::http::header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return false;
    };
    if origins.next().is_some() {
        return true;
    }
    let Ok(origin) = origin.to_str() else {
        return true;
    };
    // The comparison normalises each side's scheme-implied default port, shared
    // with `console.rs::is_cross_origin_ingest` and `server.rs::ws_cross_origin`.
    RequestAuthority::of(parts).is_none_or(|authority| {
        crate::http_header::origin_host_mismatch(origin, authority.as_str())
    })
}

/// The axum middleware. Validates CSRF on mutating, non-exempt requests; passes
/// everything else through. Reads only headers (the Ipe.Web POST body is JSON
/// with the token in `X-Ipê-Csrf`, so no body buffering is needed).
pub async fn csrf_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !csrf_enabled() {
        return next.run(req).await;
    }
    let method = req.method().clone();
    let mutating = matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::DELETE
            | axum::http::Method::PATCH
    );
    let path = req.uri().path().to_string();
    if !mutating || is_exempt_path(&path) {
        return next.run(req).await;
    }

    let (parts, body) = req.into_parts();
    if origin_mismatch(origin_check(), frame_ancestors().is_some(), &parts) {
        telemetry::record_log("warn", "csrf.rejected reason=origin-mismatch");
        return (StatusCode::FORBIDDEN, "{\"status\":\"csrf_origin\"}").into_response();
    }
    let headers = &parts.headers;

    let cookie_tok =
        cookie_value(headers, &csrf_cookie_name_for(&super::web_base_path())).unwrap_or_default();
    let header_tok = headers
        .get(CSRF_HEADER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    // csrf_pair_valid: well-formedness of BOTH tokens (structural gate) then
    // constant-time equality. Fail-closed — any malformed, missing, or
    // mismatched pair is rejected. See `server::csrf_pair_valid` for the
    // ordering rationale.
    if !csrf_pair_valid(&cookie_tok, header_tok) {
        telemetry::record_log("warn", "csrf.rejected reason=invalid");
        return (StatusCode::FORBIDDEN, "{\"status\":\"csrf_invalid\"}").into_response();
    }
    next.run(axum::extract::Request::from_parts(parts, body))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The head of a request to `uri` carrying each of `origins` as an `Origin`
    /// header and each of `hosts` as a `Host` header.
    fn head(uri: &str, origins: &[&[u8]], hosts: &[&[u8]]) -> Parts {
        let mut builder = axum::http::Request::builder().method("POST").uri(uri);
        for origin in origins {
            builder = builder.header(
                axum::http::header::ORIGIN,
                axum::http::HeaderValue::from_bytes(origin).unwrap(),
            );
        }
        for host in hosts {
            builder = builder.header(
                axum::http::header::HOST,
                axum::http::HeaderValue::from_bytes(host).unwrap(),
            );
        }
        builder.body(()).unwrap().into_parts().0
    }

    /// The switch an `IPE_WEB_CSRF_ORIGIN_CHECK` lookup of `raw` reads as.
    fn switch_when(raw: Option<&str>) -> Result<EnvFlag, crate::env_grammar::EnvRefusal> {
        WEB_CSRF_ORIGIN_CHECK.parse(raw.map(str::to_owned).ok_or(std::env::VarError::NotPresent))
    }

    /// With the switch unset, a cross-origin request is refused: the check is on by default.
    #[test]
    fn mismatched_origin_is_refused_with_the_switch_unset() {
        let check = switch_when(None).unwrap();
        assert_eq!(check, EnvFlag::On);
        let cross = head(
            "/_ipe/event",
            &[b"https://evil.example"],
            &[b"victim.example"],
        );
        assert!(origin_mismatch(check, false, &cross));
        let same = head(
            "/_ipe/event",
            &[b"https://victim.example"],
            &[b"victim.example"],
        );
        assert!(!origin_mismatch(check, false, &same));
    }

    /// An `Origin` on a request naming no authority at all is refused, never
    /// passed for want of anything to compare against.
    #[test]
    fn origin_without_any_authority_is_refused() {
        let absent = head("/_ipe/event", &[b"https://victim.example"], &[]);
        assert_eq!(RequestAuthority::of(&absent), None);
        assert!(origin_mismatch(EnvFlag::On, false, &absent));
        let empty_host = head("/_ipe/event", &[b"https://victim.example"], &[b""]);
        assert!(origin_mismatch(EnvFlag::On, false, &empty_host));
    }

    /// Without a `Host`, the target URI's authority (HTTP/2 `:authority`) is compared.
    #[test]
    fn uri_authority_stands_in_for_an_absent_host() {
        let same = head(
            "https://victim.example/_ipe/event",
            &[b"https://victim.example"],
            &[],
        );
        assert_eq!(
            RequestAuthority::of(&same).map(RequestAuthority::as_str),
            Some("victim.example")
        );
        assert!(!origin_mismatch(EnvFlag::On, false, &same));
        let cross = head(
            "https://victim.example/_ipe/event",
            &[b"https://evil.example"],
            &[],
        );
        assert!(origin_mismatch(EnvFlag::On, false, &cross));
    }

    /// A `Host` that disagrees with the target URI's authority names no single
    /// authority, so the `Origin` matching either one is refused; an agreeing
    /// pair is admitted.
    #[test]
    fn host_disagreeing_with_the_target_is_refused() {
        let uri = "https://victim.example/_ipe/event";
        for origin in [&b"https://victim.example"[..], &b"https://evil.example"[..]] {
            let split = head(uri, &[origin], &[b"evil.example"]);
            assert_eq!(RequestAuthority::of(&split), None);
            assert!(origin_mismatch(EnvFlag::On, false, &split));
        }
        let agreeing = head(uri, &[b"https://victim.example"], &[b"victim.example"]);
        assert!(!origin_mismatch(EnvFlag::On, false, &agreeing));
    }

    /// Two `Host` headers name no single authority; the request is refused even
    /// when the first matches the `Origin`.
    #[test]
    fn two_hosts_are_refused() {
        let two = head(
            "/_ipe/event",
            &[b"https://victim.example"],
            &[b"victim.example", b"evil.example"],
        );
        assert_eq!(RequestAuthority::of(&two), None);
        assert!(origin_mismatch(EnvFlag::On, false, &two));
    }

    /// A `Host` that is not visible ASCII is refused, never replaced by another
    /// authority source.
    #[test]
    fn unreadable_host_is_refused() {
        let bad = head(
            "https://victim.example/_ipe/event",
            &[b"https://victim.example"],
            &[b"victim.\xffexample"],
        );
        assert!(origin_mismatch(EnvFlag::On, false, &bad));
    }

    /// Two `Origin` headers are refused even when the first is same-origin.
    #[test]
    fn two_origins_are_refused() {
        let two = head(
            "/_ipe/event",
            &[b"https://victim.example", b"https://evil.example"],
            &[b"victim.example"],
        );
        assert!(origin_mismatch(EnvFlag::On, false, &two));
    }

    /// An opaque `null` origin (sandboxed frame, `data:` document) is refused.
    #[test]
    fn null_origin_is_refused() {
        let null = head("/_ipe/event", &[b"null"], &[b"victim.example"]);
        assert!(origin_mismatch(EnvFlag::On, false, &null));
    }

    /// An `Origin` that is not visible ASCII is refused, not read as absent.
    #[test]
    fn unreadable_origin_is_refused() {
        let bad = head(
            "/_ipe/event",
            &[b"https://\xffvictim.example"],
            &[b"victim.example"],
        );
        assert!(origin_mismatch(EnvFlag::On, false, &bad));
    }

    /// The switch spellings fold ASCII case: `On` turns the check on, `off` turns it off.
    #[test]
    fn switch_spellings_fold_case() {
        let cross = head(
            "/_ipe/event",
            &[b"https://evil.example"],
            &[b"victim.example"],
        );
        let on = switch_when(Some("On")).unwrap();
        assert_eq!(on, EnvFlag::On);
        assert!(origin_mismatch(on, false, &cross));
        let off = switch_when(Some("off")).unwrap();
        assert_eq!(off, EnvFlag::Off);
        assert!(!origin_mismatch(off, false, &cross));
    }

    /// A value spelling no switch is refused, naming the variable, never read as off.
    #[test]
    fn unparseable_switch_is_refused() {
        for raw in ["maybe", "", " on", "yes"] {
            let refusal = switch_when(Some(raw)).unwrap_err();
            assert_eq!(refusal.name(), "IPE_WEB_CSRF_ORIGIN_CHECK", "{raw:?}");
        }
        assert!(matches!(
            switch_when(Some("maybe")).unwrap_err(),
            crate::env_grammar::EnvRefusal::Malformed { .. }
        ));
    }

    /// Frame-ancestors mode and an `Origin`-less request are not judged by the check.
    #[test]
    fn framed_or_origin_less_requests_pass_the_check() {
        let cross = head(
            "/_ipe/event",
            &[b"https://evil.example"],
            &[b"victim.example"],
        );
        assert!(!origin_mismatch(EnvFlag::On, true, &cross));
        let origin_less = head("/_ipe/event", &[], &[]);
        assert!(!origin_mismatch(EnvFlag::On, false, &origin_less));
    }

    fn well_formed_tok() -> String {
        // 64 lowercase hex chars — the exact shape gen_token() produces.
        "a".repeat(64)
    }

    // csrf_pair_valid: matching well-formed pair → accepted.
    #[test]
    fn pair_valid_matching_well_formed_accepted() {
        let tok = well_formed_tok();
        assert!(csrf_pair_valid(&tok, &tok));
    }

    // The dev-only appearance-hot-swap POST is CSRF-exempt: it carries its own
    // `X-Ipe-Hot-Token` control instead of the browser CSRF cookie. An ordinary
    // app POST stays subject to CSRF.
    #[test]
    fn hot_appearance_is_csrf_exempt_but_ordinary_posts_are_not() {
        assert!(is_exempt_path("/_ipe/hot-appearance"));
        assert!(!is_exempt_path("/_ipe/event"));
        assert!(!is_exempt_path("/_ipe/port"));
    }

    // The dev-only transition-hot-swap POST is CSRF-exempt for the same reason as
    // the appearance one: a loopback `ipe dev watch` call carrying its own
    // `X-Ipe-Hot-Token`, mounted only under the dev overlay gate.
    #[test]
    fn hot_transition_is_csrf_exempt() {
        assert!(is_exempt_path("/_ipe/hot-transition"));
        assert!(!is_exempt_path("/_ipe/event"));
    }

    // The dev-only additive-`Msg`-set POST is CSRF-exempt for the same reason as
    // the appearance/transition ones: a loopback `ipe dev watch` call carrying its own
    // `X-Ipe-Hot-Token`, mounted only under the dev overlay gate.
    #[test]
    fn hot_msg_is_csrf_exempt() {
        assert!(is_exempt_path("/_ipe/hot-msg"));
        assert!(!is_exempt_path("/_ipe/event"));
    }

    // The dev-only subscription-hot-swap POST is CSRF-exempt for the same reason
    // as the transition one: a loopback `ipe dev watch` call carrying its own
    // `X-Ipe-Hot-Token`, mounted only under the dev overlay gate.
    #[test]
    fn hot_subs_is_csrf_exempt() {
        assert!(is_exempt_path("/_ipe/hot-subs"));
        assert!(!is_exempt_path("/_ipe/event"));
    }

    // The dev-only init-datum and Cmd-wiring hot-swap POSTs are CSRF-exempt for
    // the same reason as the appearance and transition siblings: loopback `ipe
    // dev watch` calls authenticated by `X-Ipe-Hot-Token`, mounted only under the
    // dev overlay gate, never reachable in a production build.
    #[test]
    fn hot_init_and_hot_wiring_are_csrf_exempt() {
        assert!(is_exempt_path("/_ipe/hot-init"));
        assert!(is_exempt_path("/_ipe/hot-wiring"));
        // A non-hot path under /_ipe stays non-exempt.
        assert!(!is_exempt_path("/_ipe/event"));
    }

    // csrf_pair_valid: matching but malformed pair (too short, not 64-hex) → rejected.
    #[test]
    fn pair_valid_matching_malformed_too_short_rejected() {
        assert!(!csrf_pair_valid("x", "x"));
    }

    #[test]
    fn pair_valid_matching_malformed_wrong_length_rejected() {
        let tok = "a".repeat(63);
        assert!(!csrf_pair_valid(&tok, &tok));
    }

    #[test]
    fn pair_valid_matching_malformed_non_hex_rejected() {
        // 64 chars but contains non-hex characters.
        let tok = "g".repeat(64);
        assert!(!csrf_pair_valid(&tok, &tok));
    }

    // csrf_pair_valid: well-formed but mismatched pair → rejected.
    #[test]
    fn pair_valid_well_formed_mismatched_rejected() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert!(!csrf_pair_valid(&a, &b));
    }

    // csrf_pair_valid: empty tokens → rejected.
    #[test]
    fn pair_valid_empty_rejected() {
        assert!(!csrf_pair_valid("", ""));
        assert!(!csrf_pair_valid("", &well_formed_tok()));
        assert!(!csrf_pair_valid(&well_formed_tok(), ""));
    }

    // SSOT: gen_token() produces a token that passes token_is_well_formed.
    #[test]
    fn gen_token_passes_well_formed() {
        let tok = gen_token();
        assert!(
            token_is_well_formed(&tok),
            "gen_token() must produce a well-formed token; got: {tok}"
        );
    }

    // SSOT: the single gen_token/token_is_well_formed definition is shared;
    // verify gen_token and csrf_pair_valid agree (a freshly generated pair passes).
    #[test]
    fn gen_token_csrf_pair_valid_agree() {
        let tok = gen_token();
        assert!(csrf_pair_valid(&tok, &tok));
    }

    // Per-app cookie name tests (dev mode: cookies_secure() is false in tests
    // because no production env var is set, so the prefix is `__ipe_csrf`).

    // Root app gets the bare cookie name with no suffix.
    #[test]
    fn cookie_name_for_root_has_no_suffix() {
        let name = csrf_cookie_name_for("");
        // Prefix only — no trailing characters.
        assert!(
            name.text() == "__Host-ipe_csrf" || name.text() == "__ipe_csrf",
            "root app must produce a bare name, got: {name}"
        );
        // No app-specific suffix: the name ends immediately after the base.
        assert!(!name.text().ends_with('_'));
    }

    // Two sub-apps with different base paths get different cookie names,
    // so a CSRF token set by one app cannot collide with the other's cookie.
    #[test]
    fn cookie_name_for_different_bases_are_distinct() {
        let host_name = csrf_cookie_name_for("");
        let shop_name = csrf_cookie_name_for("/shop");
        let blog_name = csrf_cookie_name_for("/blog");

        assert_ne!(
            host_name, shop_name,
            "host and /shop must have distinct CSRF cookie names"
        );
        assert_ne!(
            host_name, blog_name,
            "host and /blog must have distinct CSRF cookie names"
        );
        assert_ne!(
            shop_name, blog_name,
            "/shop and /blog must have distinct CSRF cookie names"
        );
    }

    // A token minted for app A does not validate against app B's cookie name.
    // Simulates: browser sends Cookie: <app_b_name>=<token_a>; header has token_a.
    // The validator for app B reads cookie under app_b_name — but the cookie was
    // set under app_a_name, so the cookie jar contains no app_b_name entry →
    // cookie_tok is empty → csrf_pair_valid fails.
    #[test]
    fn token_minted_for_app_a_does_not_satisfy_app_b_validator() {
        let name_a = csrf_cookie_name_for("/shop");
        let name_b = csrf_cookie_name_for("/admin");
        assert_ne!(name_a, name_b);

        let token_a = well_formed_tok();

        // Build a Cookie header carrying token_a under app A's cookie name.
        let raw_cookie = format!("{name_a}={token_a}");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            axum::http::HeaderValue::from_str(&raw_cookie).unwrap(),
        );

        // App A's validator finds its cookie and the pair matches.
        let read_a = cookie_value(&headers, &name_a).unwrap_or_default();
        assert!(
            csrf_pair_valid(&read_a, &token_a),
            "app A must validate its own token"
        );

        // App B's validator reads under name_b → miss → empty string → fails.
        let read_b = cookie_value(&headers, &name_b).unwrap_or_default();
        assert!(
            !csrf_pair_valid(&read_b, &token_a),
            "app B must not accept a token minted for app A"
        );
    }

    /// The typed CSRF line keeps the exact bytes of each posture's line, so an
    /// existing browser CSRF cookie is replaced, never duplicated.
    #[test]
    fn csrf_set_cookie_keeps_the_csrf_line_bytes() {
        let tok = well_formed_tok();
        let attrs = if frame_ancestors().is_some() {
            "; Path=/; HttpOnly; SameSite=None; Secure"
        } else if cookies_secure() {
            "; Path=/; HttpOnly; SameSite=Strict; Secure"
        } else {
            "; Path=/; HttpOnly; SameSite=Strict"
        };
        for base in ["", "/shop"] {
            let expected = format!("{}={tok}{attrs}", csrf_cookie_name_for(base));
            assert_eq!(csrf_set_cookie(&tok, base).as_str(), expected);
        }
    }

    // The Set-Cookie string always carries Path=/ regardless of the base path,
    // so the __Host- security invariant holds for every app.
    #[test]
    fn set_cookie_always_path_root() {
        let cookie_root = csrf_set_cookie(&well_formed_tok(), "");
        let cookie_sub = csrf_set_cookie(&well_formed_tok(), "/shop");

        assert!(
            cookie_root.contains("Path=/"),
            "root app Set-Cookie must carry Path=/"
        );
        assert!(
            cookie_sub.contains("Path=/"),
            "sub-app Set-Cookie must carry Path=/ (not the sub-app path)"
        );
    }

    // The sub-app cookie name contains only RFC 6265-safe cookie-name characters
    // (ASCII alphanumeric, `-`, `_`) — never a raw `/` or other separator that
    // would break the `Set-Cookie` header syntax.
    #[test]
    fn cookie_name_characters_are_rfc6265_safe() {
        for base in &["/shop", "/_ipe/console", "/a/b/c", "/foo-bar_baz"] {
            let name = csrf_cookie_name_for(base);
            // RFC 6265 cookie-name: visible US-ASCII chars except delimiters.
            // Our transform maps everything non-alphanumeric to `_`, so the name
            // contains only alphanumerics, `_`, and `-` (from the `__Host-` prefix).
            let bad: Vec<char> = name
                .as_str()
                .chars()
                .filter(|&c| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
                .collect();
            assert!(
                bad.is_empty(),
                "cookie name for base={base:?} contains unsafe chars {bad:?}: {name}"
            );
        }
    }
}

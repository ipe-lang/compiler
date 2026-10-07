//! Ipe Console — the operator dashboard mounted at `/_ipe/console`, plus the
//! observability federation receiver. The in-RAM tier:
//! a plain-HTML shell that polls JSON `/_ipe/console/api/*` endpoints backed by
//! the `telemetry` ring buffers, and a `/_ipe/observability/ingest` POST that
//! folds a sub-app's batched logs into the same rings.
//!
//! Unlike the separate-process console path, this
//! proxies it), the Rust console is served in-process directly off the Web
//! router — no extra process, same data. No panic vectors.

use crate::telemetry::{self, ConsoleAuthMode, ConsoleAuthResolution, Posture};
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

const fn json_ct() -> (header::HeaderName, &'static str) {
    (header::CONTENT_TYPE, "application/json")
}

/// Boot-time decision: should the console be mounted at all?
/// `false` → the caller skips the console entirely (in-process or proxy).
///
/// Conditions that suppress the console mount:
/// - sub-app context: the parent owns its own console; a nested app must not
///   recursively mount one (`IPE_WEB_BASE_PATH` non-empty);
/// - explicit opt-out via `IPE_CONSOLE_EMBED=off|0|false`;
/// - `IPE_CONSOLE_AUTH` resolving to `off` (operator declared the surface
///   absent, or set an unrecognised value — fail closed);
/// - production, or a dev posture off a loopback listener (`unset-prod`),
///   without a usable admin credential (fail-closed — no silent open-to-world
///   mount; a metrics credential never mounts the console).
///
/// This function is reqwest-free; it lives here so the mount decision is
/// available regardless of whether `http_client` is compiled in.
pub fn gate_allows() -> bool {
    if crate::system::read_env_var("IPE_WEB_BASE_PATH")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return false;
    }
    if matches!(
        crate::system::read_env_var("IPE_CONSOLE_EMBED").as_deref(),
        Ok("off") | Ok("0") | Ok("false")
    ) {
        return false;
    }
    let resolved = ConsoleAuthResolution::from_env();
    if resolved.mode == ConsoleAuthMode::Off {
        return false;
    }
    let needs_credential =
        resolved.posture == Posture::Production || resolved.mode == ConsoleAuthMode::UnsetProd;
    !(needs_credential && !admin_credential().is_configured())
}

/// The console page's one inline stylesheet; the console policy admits it by
/// its hash.
pub const CONSOLE_CSS: &str = r#"
 body{font-family:ui-monospace,monospace;background:#12141c;color:#dfe3ee;margin:0;padding:16px}
 h1{font-size:16px;color:#8ec8a8} .tab{cursor:pointer;padding:4px 10px;margin-right:6px;border:1px solid #2a2f40;border-radius:4px;display:inline-block}
 .tab.on{background:#2a2f40} pre{background:#0c0e14;padding:10px;border-radius:4px;overflow:auto;max-height:70vh}
 .err{color:#e88} .lvl{color:#7a86a8}
"#;

/// The console page's one inline script; the console policy admits it by its
/// hash.
pub const CONSOLE_JS: &str = r#"
 let tab="logs";
 async function j(u){try{const r=await fetch(u);return await r.json()}catch(e){return null}}
 async function ov(){const o=await j("/_ipe/console/api/overview");if(o)document.getElementById("ov").textContent=
   "requests="+o.requests+"  errors="+o.errors;}
 function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
 function fmt(es){return (es||[]).map(e=>{const d=new Date(e.ts).toISOString().slice(11,19);
   return "<span class='lvl'>"+esc(d)+" "+esc(e.level)+"</span> "+(e.level=="error"?"<span class='err'>":"")+
   esc(e.message)+(e.level=="error"?"</span>":"");}).join("\n");}
 async function refresh(){const es=await j("/_ipe/console/api/"+tab);
   document.getElementById("out").innerHTML=fmt(es);ov();}
 document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{
   document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));t.classList.add("on");
   tab=t.dataset.t;refresh();});
 refresh();setInterval(refresh,2000);
"#;

/// The console page: [`CONSOLE_CSS`] and [`CONSOLE_JS`] embedded verbatim, so
/// the policy hashes match the bytes served.
fn console_page() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| {
        format!(
            r#"<!doctype html><html><head><meta charset="utf-8">
<title>Ipe Console</title>
<style>{CONSOLE_CSS}</style></head><body>
<h1>Ipe Console</h1>
<div id="ov"></div>
<div><span class="tab on" data-t="logs">Logs</span><span class="tab" data-t="errors">Errors</span></div>
<pre id="out">loading…</pre>
<script>{CONSOLE_JS}</script></body></html>"#
        )
    })
}

/// `GET /_ipe/console` — the plain-HTML dashboard shell (no framework, no CSS
/// deps). Polls the api endpoints below.
///
/// The response carries the console policy, the shared security headers and
/// `no-store`; a refused framing configuration answers `500`.
pub async fn console_html() -> axum::response::Response {
    let resp = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        console_page(),
    )
        .into_response();
    crate::server::with_security_headers(
        resp,
        telemetry::security_headers(telemetry::HeaderProfile::Policy(
            crate::csp::Profile::Console,
        )),
    )
}

/// `GET /_ipe/console/api/overview` — request + error counters.
pub async fn api_overview() -> impl IntoResponse {
    let body = format!(
        r#"{{"requests":{},"errors":{}}}"#,
        telemetry::requests_total(),
        telemetry::errors_total()
    );
    (StatusCode::OK, [json_ct()], body)
}

/// `GET /_ipe/console/api/logs` — recent log ring (most recent 200).
pub async fn api_logs() -> impl IntoResponse {
    (
        StatusCode::OK,
        [json_ct()],
        telemetry::entries_json(&telemetry::recent_logs(200)),
    )
}

/// `GET /_ipe/console/api/errors` — recent error ring.
pub async fn api_errors() -> impl IntoResponse {
    (
        StatusCode::OK,
        [json_ct()],
        telemetry::entries_json(&telemetry::recent_errors(200)),
    )
}

/// `GET /_ipe/console/api/traces` — recent completed `Ipe.Trace.span`s.
pub async fn api_traces() -> impl IntoResponse {
    (StatusCode::OK, [json_ct()], telemetry::spans_json(200))
}

/// `GET /_ipe/console/api/metrics-summary` — the parsed counter snapshot the
/// dashboard renders (mirror of  parsed Prometheus summary).
pub async fn api_metrics_summary() -> impl IntoResponse {
    let body = format!(
        r#"{{"ipe_web_requests_total":{},"ipe_web_errors_total":{}}}"#,
        telemetry::requests_total(),
        telemetry::errors_total()
    );
    (StatusCode::OK, [json_ct()], body)
}

/// The credential an `Authorization` header presents.
///
/// `Bearer <tok>` or `Basic base64(user:tok)` (the Prometheus `basic_auth`
/// scrape path — any username, the password is the token). Anything else
/// presents nothing.
struct Presented(String);

impl Presented {
    fn from_header(auth: &str) -> Option<Self> {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        if let Some(bearer) = auth.strip_prefix("Bearer ") {
            return Some(Self(bearer.to_owned()));
        }
        let b64 = auth.strip_prefix("Basic ")?;
        let raw = B64.decode(b64.trim()).ok()?;
        let creds = String::from_utf8(raw).ok()?;
        let (_user, pw) = creds.split_once(':')?;
        Some(Self(pw.to_owned()))
    }
}

/// A role-bearing console credential, compared only in constant time.
trait RoleToken {
    fn token_bytes(&self) -> &[u8];
}

/// The admin credential: authorizes `/_ipe/console*` and `/_ipe/metrics`.
struct AdminToken(String);

/// The metrics credential: authorizes `/_ipe/metrics` only.
struct MetricsToken(String);

impl RoleToken for AdminToken {
    fn token_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl RoleToken for MetricsToken {
    fn token_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// One source in a credential's precedence chain.
enum TokenSource {
    /// Absent or empty: defer to the next source.
    Unset,
    /// A non-empty token.
    Set(String),
    /// Present but not valid UTF-8: the role is refused, never deferred.
    NotUnicode,
}

impl TokenSource {
    fn env(name: &str) -> Self {
        match crate::system::read_env_var(name) {
            Ok(token) if token.is_empty() => Self::Unset,
            Ok(token) => Self::Set(token),
            Err(std::env::VarError::NotPresent) => Self::Unset,
            Err(std::env::VarError::NotUnicode(_)) => Self::NotUnicode,
        }
    }

    /// The in-code `Console.*Token` sealed `Secret`, revealed only here.
    fn in_code(kind: crate::app_config::ConsoleTokenKind) -> Self {
        match crate::app_config::resolve_console_token(kind) {
            Some(token) if !token.is_empty() => Self::Set(token),
            Some(_) | None => Self::Unset,
        }
    }
}

/// A role's resolved credential.
enum Credential<T> {
    /// No source configures the role: no token of this role is accepted.
    Unset,
    /// The highest-precedence source is garbled: no token of this role is
    /// accepted.
    Unusable,
    /// The configured token.
    Configured(T),
}

impl<T: RoleToken> Credential<T> {
    /// Walk `chain` in precedence order. The first `Set` source wins; a
    /// `NotUnicode` source ahead of it makes the role `Unusable`.
    fn resolve(chain: impl IntoIterator<Item = TokenSource>, wrap: fn(String) -> T) -> Self {
        for source in chain {
            match source {
                TokenSource::Unset => {}
                TokenSource::Set(token) => return Self::Configured(wrap(token)),
                TokenSource::NotUnicode => return Self::Unusable,
            }
        }
        Self::Unset
    }

    const fn is_configured(&self) -> bool {
        matches!(self, Self::Configured(_))
    }

    /// Constant-time match against the presented credential (length is
    /// non-secret metadata).
    fn admits(&self, presented: &Presented) -> bool {
        match self {
            Self::Configured(token) => {
                crate::ct_eq::ct_bytes_eq(presented.0.as_bytes(), token.token_bytes())
            }
            Self::Unset | Self::Unusable => false,
        }
    }
}

/// Admin chain: `IPE_ADMIN_TOKEN` › in-code `Console.adminToken` › legacy
/// `IPE_CONSOLE_TOKEN`. Env wins over the in-code sealed `Secret`.
fn admin_credential() -> Credential<AdminToken> {
    use crate::app_config::ConsoleTokenKind;
    Credential::resolve(
        std::iter::once_with(|| TokenSource::env("IPE_ADMIN_TOKEN"))
            .chain(std::iter::once_with(|| {
                TokenSource::in_code(ConsoleTokenKind::Admin)
            }))
            .chain(std::iter::once_with(|| {
                TokenSource::env("IPE_CONSOLE_TOKEN")
            })),
        AdminToken,
    )
}

/// Metrics chain: `IPE_METRICS_TOKEN` › in-code `Console.metricsToken`.
fn metrics_credential() -> Credential<MetricsToken> {
    use crate::app_config::ConsoleTokenKind;
    Credential::resolve(
        std::iter::once_with(|| TokenSource::env("IPE_METRICS_TOKEN")).chain(std::iter::once_with(
            || TokenSource::in_code(ConsoleTokenKind::Metrics),
        )),
        MetricsToken,
    )
}

/// The credentials each gated surface may accept.
struct Credentials {
    admin: Credential<AdminToken>,
    metrics: Credential<MetricsToken>,
}

impl Credentials {
    fn from_env(surface: Surface) -> Self {
        Self {
            admin: admin_credential(),
            metrics: match surface {
                Surface::Console => Credential::Unset,
                Surface::Metrics => metrics_credential(),
            },
        }
    }

    /// `/_ipe/console*` accepts the admin credential only; `/_ipe/metrics`
    /// accepts admin or metrics. Both comparisons always run.
    fn admit(&self, surface: Surface, presented: &Presented) -> bool {
        let admin = self.admin.admits(presented);
        match surface {
            Surface::Console => admin,
            Surface::Metrics => admin | self.metrics.admits(presented),
        }
    }
}

/// The credential-gated observability surface a request targets.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Surface {
    /// `/_ipe/console*`: logs, errors, spans. Admin credential only.
    Console,
    /// `/_ipe/metrics`: the Prometheus scrape. Admin or metrics credential.
    Metrics,
}

impl Surface {
    /// The gated surface `path` targets; `None` for every other path.
    #[must_use]
    pub fn of_path(path: &str) -> Option<Self> {
        if path == "/_ipe/metrics" {
            Some(Self::Metrics)
        } else if path.starts_with("/_ipe/console") {
            Some(Self::Console)
        } else {
            None
        }
    }
}

/// The console-auth mode label for the `[ipe.console] … mode=<m>` startup log.
///
/// Derived from the one `IPE_CONSOLE_AUTH` parse, `ConsoleAuthMode::from_env`.
pub fn console_auth_mode_label() -> &'static str {
    ConsoleAuthMode::from_env().label()
}

/// Per-request auth gate for the console + metrics surface.
///
/// Returns `Some(response)` when the request must be REFUSED.
pub fn gate_blocked(
    surface: Surface,
    headers: &axum::http::HeaderMap,
) -> Option<axum::response::Response> {
    gate_decision(ConsoleAuthMode::from_env(), surface, headers, || {
        Credentials::from_env(surface)
    })
}

/// The gate as a pure function of the resolved mode and the request.
///
/// `Off` → 404 (surface absent). `App` → 501 (not supported on this runtime;
/// fail closed). `DevOpen` → open. `Token` and `UnsetProd` → a credential of a
/// role `surface` accepts is required, else 401 — an explicit `token` is
/// enforced in every posture, dev included. With no usable credential every
/// such request is refused. `credentials` is read only when one is required.
fn gate_decision(
    mode: ConsoleAuthMode,
    surface: Surface,
    headers: &axum::http::HeaderMap,
    credentials: impl FnOnce() -> Credentials,
) -> Option<axum::response::Response> {
    match mode {
        ConsoleAuthMode::Off => Some((StatusCode::NOT_FOUND, "console disabled").into_response()),
        // The row-poly `consoleAuth` callback is not wired in the Rust runtime:
        // a clear 501 rather than a 401 suggesting a better token would help.
        ConsoleAuthMode::App => Some(
            (
                StatusCode::NOT_IMPLEMENTED,
                "IPE_CONSOLE_AUTH=app (row-poly consoleAuth callback) is not yet \
                 supported on the Rust runtime; use token/off or IPE_ADMIN_TOKEN",
            )
                .into_response(),
        ),
        ConsoleAuthMode::DevOpen => None,
        ConsoleAuthMode::Token | ConsoleAuthMode::UnsetProd => {
            token_blocked(surface, headers, credentials)
        }
    }
}

/// `Some(401)` unless the `Authorization` header carries a credential of a
/// role `surface` accepts.
fn token_blocked(
    surface: Surface,
    headers: &axum::http::HeaderMap,
    credentials: impl FnOnce() -> Credentials,
) -> Option<axum::response::Response> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(Presented::from_header);
    let authed = presented.is_some_and(|p| credentials().admit(surface, &p));
    if authed {
        return None;
    }
    // Audit the denial so an operator sees brute-force / probing attempts.
    telemetry::record_log(
        "warn",
        "console.auth.denied reason=bad-or-missing-credentials",
    );
    // `WWW-Authenticate` so a Prometheus `basic_auth` scraper gets a challenge
    // it can act on instead of a bare 401.
    Some(
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"ipe-metrics\"")],
            "console requires a Bearer or Basic token of an accepted role",
        )
            .into_response(),
    )
}

/// `POST /_ipe/observability/ingest` — federation receiver. Accepts a JSON array
/// of `{ "level": "...", "message": "..." }` (a sub-app's batched logs) and folds
/// them into the local rings. Malformed bodies are accepted as 204 (drop) rather
/// than erroring — telemetry must never break the caller.
///
/// Auth : a shared secret in `X-Ipê-Ingest-Token`, constant-time compared
/// against `IPE_INGEST_TOKEN`. With the token set, only a matching request is
/// accepted. With the token unset, the endpoint fails CLOSED in production
/// (401) and, in dev, accepts only same-origin requests — a cross-origin POST
/// (the CSRF-log-injection shape) is rejected (403).
pub async fn ingest(headers: axum::http::HeaderMap, body: String) -> axum::response::Response {
    if let Some(resp) = ingest_token_blocked(&headers) {
        return resp;
    }
    // Two accepted shapes: a bare array of `{level, message}` (legacy), or the
    // federation push object `{ "logs": [...], "spans": [...] }` (from
    // push_exporter::build_payload). Fold both into the local rings.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        match v {
            serde_json::Value::Array(items) => {
                for it in items {
                    fold_log(&it);
                }
            }
            serde_json::Value::Object(_) => {
                // Iterate the arrays by reference — no `.cloned()` of the whole
                // log/span batch (fold_log + the span reader both take `&Value`).
                if let Some(serde_json::Value::Array(logs)) = v.get("logs") {
                    for it in logs {
                        fold_log(it);
                    }
                }
                if let Some(serde_json::Value::Array(spans)) = v.get("spans") {
                    for it in spans {
                        let name = it.get("name").and_then(|x| x.as_str()).unwrap_or("");
                        let dur_us = it.get("durUs").and_then(|x| x.as_u64()).unwrap_or(0);
                        let ok = it.get("ok").and_then(|x| x.as_bool()).unwrap_or(true);
                        if !name.is_empty() {
                            // Sanitise the untrusted span name (same terminal-escape
                            // injection vector as fold_log's message).
                            telemetry::record_span(&sanitise_ingest(name), dur_us, ok);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Escape every log-hazard character and cap the length of UNTRUSTED ingest text.
///
/// The text enters the operator console rings, which render to a terminal AND
/// re-export over OTLP. A malicious or compromised sub-app could otherwise
/// inject ANSI/CSI/OSC escapes, NUL, newlines, line separators, bidi
/// overrides, zero-width splits or hidden tag-block text — forged log lines,
/// clear-screen, cursor moves, reordered or invisible content — into the
/// operator's terminal. The set is the runtime's one predicate,
/// `system::is_log_hazard`; each hazard becomes a visible escape
/// (`system::scrub_log_controls_capped`), so a record with a hidden character
/// never reads as one without it. First-party `Log.*` does NOT route through
/// ingest, so it is unaffected.
fn sanitise_ingest(s: &str) -> String {
    const MAX_INGEST_BYTES: usize = 8192;
    crate::system::scrub_log_controls_capped(s, MAX_INGEST_BYTES)
}

/// Fold one ingested log object `{level, message}` into the local rings.
fn fold_log(it: &serde_json::Value) {
    let level = it.get("level").and_then(|v| v.as_str()).unwrap_or("info");
    let message = it.get("message").and_then(|v| v.as_str()).unwrap_or("");
    if !message.is_empty() {
        telemetry::record_log(&sanitise_ingest(level), &sanitise_ingest(message));
    }
}

/// True when `Origin` is present AND does not match `Host` — i.e. this is a
/// cross-origin request. Absent `Origin` (same-origin fetch/XHR, curl,
/// server-to-server pushes from `push_exporter.rs`) is NOT flagged: those
/// callers never send a hostile cross-origin request by construction, and
/// requiring `Origin` would break legitimate non-browser ingest pushes.
/// Mirrors `csrf.rs::origin_mismatch`'s same-origin comparison (via the
/// shared `origin_host_mismatch` helper, also used by
/// `server.rs::ws_cross_origin` — normalizes away each side's scheme-implied
/// default port so the three never drift to different behavior), applied
/// unconditionally here (not opt-in) since it's the ONLY defense available
/// when `IPE_INGEST_TOKEN` is unset.
fn is_cross_origin_ingest(headers: &axum::http::HeaderMap) -> bool {
    let origin = match headers
        .get(axum::http::header::ORIGIN)
        .and_then(|h| h.to_str().ok())
    {
        Some(o) => o,
        None => return false,
    };
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    crate::http_header::origin_host_mismatch(origin, host)
}

/// The ingest gate over the process environment: the configured
/// `IPE_INGEST_TOKEN` (env, then in-code `Console.ingestToken`) and
/// [`telemetry::dev_surface_from_env`].
fn ingest_token_blocked(headers: &axum::http::HeaderMap) -> Option<axum::response::Response> {
    let want = crate::system::read_env_var("IPE_INGEST_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        // In-code `Console.ingestToken` (a sealed `Secret`) below the env
        // override — env wins; the token is revealed only here, never logged.
        .or_else(|| {
            crate::app_config::resolve_console_token(crate::app_config::ConsoleTokenKind::Ingest)
                .filter(|t| !t.is_empty())
        });
    ingest_decision(
        headers,
        want.as_deref(),
        telemetry::dev_surface_from_env().as_ref(),
    )
}

/// `Some(401)` when a token is configured and the `X-Ipê-Ingest-Token` header
/// is absent or wrong (constant-time compare). With no token, `Some(401)`
/// unless `dev` proves a dev surface (a dev-intent binary in a dev posture
/// whose every listener is loopback); there, a cross-origin browser POST (log-injection CSRF shape —
/// see `is_cross_origin_ingest`) is still refused.
pub(super) fn ingest_decision(
    headers: &axum::http::HeaderMap,
    want: Option<&str>,
    dev: Option<&telemetry::DevSurface>,
) -> Option<axum::response::Response> {
    let want = match want {
        Some(t) => t,
        None => {
            // An unauthenticated ingest folds attacker-supplied telemetry
            // straight into the operator console (log-injection); a client
            // that sends no Origin passes the same-origin check below, so
            // only a loopback dev listener may run without a token.
            if dev.is_none() {
                return Some(
                    (
                        StatusCode::UNAUTHORIZED,
                        "observability ingest requires IPE_INGEST_TOKEN outside a loopback dev build",
                    )
                        .into_response(),
                );
            }
            // Dev + no token configured: the ONLY remaining defense is
            // same-origin. A same-origin fetch/XHR, curl, or a same-process
            // push (no Origin header) is allowed; a cross-origin browser POST
            // (the CSRF-log-injection shape — a `POST` with
            // `Content-Type: text/plain` and no custom header is a CORS
            // "simple request", so a malicious cross-origin page can fire it
            // without a preflight) is rejected.
            if is_cross_origin_ingest(headers) {
                return Some(
                    (
                        StatusCode::FORBIDDEN,
                        "observability ingest: cross-origin request rejected (set IPE_INGEST_TOKEN to allow federated pushes)",
                    )
                        .into_response(),
                );
            }
            return None;
        }
    };
    let got = headers
        .get("x-ipe-ingest-token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if crate::ct_eq::ct_bytes_eq(got.as_bytes(), want.as_bytes()) {
        None
    } else {
        Some(
            (
                StatusCode::UNAUTHORIZED,
                "invalid or missing X-Ipe-Ingest-Token",
            )
                .into_response(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{
        BuildPosture, ProcessScope, RawEnv, dev_intent, dev_surface, test_dev_surface,
    };

    /// Parse `IPE_CONSOLE_AUTH` as a dev-intent binary on a loopback listener
    /// would.
    fn parse_loopback(raw: RawEnv<'_>, posture: Posture) -> ConsoleAuthMode {
        ConsoleAuthMode::parse(
            raw,
            BuildPosture::Development,
            posture,
            ProcessScope::Loopback,
        )
    }

    /// Clear every input the console posture reads, then set `pairs`.
    fn seed_console_env(pairs: &[(&str, &str)]) {
        for key in ["ENV", "IPE_ENV", "IPE_CONSOLE_AUTH", "IPE_ADMIN_TOKEN"] {
            crate::system::locked_remove_var(key);
        }
        for (key, value) in pairs {
            crate::system::locked_set_var(key, value);
        }
    }

    // A release binary with nothing set: posture production, mode
    // `unset-prod`, no mount, and every unauthenticated request refused.
    #[test]
    fn release_with_nothing_set_keeps_console_closed() {
        seed_console_env(&[]);
        let resolved = ConsoleAuthResolution::from_env();
        assert_eq!(resolved.mode, ConsoleAuthMode::UnsetProd);
        if !cfg!(feature = "dev-posture") {
            assert_eq!(resolved.posture, Posture::Production);
        }
        assert!(
            !gate_allows(),
            "no admin credential: the console must not mount"
        );
        for surface in [Surface::Console, Surface::Metrics] {
            assert!(
                gate_blocked(surface, &axum::http::HeaderMap::new()).is_some(),
                "an unauthenticated {surface:?} request must be refused"
            );
        }
    }

    // `ENV=dev` with no loopback listener recorded fails closed: a release
    // binary resolves production, a dev-intent one has no dev surface.
    #[test]
    fn dev_posture_off_loopback_keeps_console_closed() {
        seed_console_env(&[("ENV", "dev")]);
        let resolved = ConsoleAuthResolution::from_env();
        let posture = if cfg!(feature = "dev-posture") {
            Posture::Dev
        } else {
            Posture::Production
        };
        assert_eq!(resolved.posture, posture);
        assert_eq!(resolved.mode, ConsoleAuthMode::UnsetProd);
        assert!(!gate_allows());
        assert!(gate_blocked(Surface::Console, &axum::http::HeaderMap::new()).is_some());
        seed_console_env(&[]);
    }

    /// The console response carries the console policy, `nosniff`,
    /// `no-store` and same-origin framing, and embeds exactly the hashed
    /// constants as its one style and one script element.
    #[tokio::test]
    async fn console_csp_and_headers() {
        let resp = console_html().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let get = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let want =
            crate::csp::ContentSecurityPolicy::for_profile(crate::csp::Profile::Console, None)
                .header_value();
        assert_eq!(get("content-security-policy"), Some(want.clone()));
        assert!(want.contains("script-src 'sha256-"), "{want}");
        assert!(!want.contains("'unsafe-inline'"), "{want}");
        assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"));
        assert_eq!(get("cache-control").as_deref(), Some("no-store"));
        assert_eq!(get("x-frame-options").as_deref(), Some("SAMEORIGIN"));
        assert!(get("referrer-policy").is_some());
        let page = console_page();
        assert_eq!(page.matches("<script").count(), 1, "{page}");
        assert_eq!(page.matches("<style").count(), 1, "{page}");
        assert!(page.contains(&format!("<script>{CONSOLE_JS}</script>")));
        assert!(page.contains(&format!("<style>{CONSOLE_CSS}</style>")));
    }

    #[test]
    fn gate_skips_in_subapp_context() {
        crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/billing");
        assert!(!gate_allows());
        crate::system::locked_remove_var("IPE_WEB_BASE_PATH");
    }

    #[test]
    fn gate_skips_on_explicit_off() {
        crate::system::locked_set_var("IPE_CONSOLE_EMBED", "off");
        assert!(!gate_allows());
        crate::system::locked_remove_var("IPE_CONSOLE_EMBED");
    }

    fn auth_headers(value: Option<&'static str>) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if let Some(v) = value {
            h.insert(
                header::AUTHORIZATION,
                axum::http::HeaderValue::from_static(v),
            );
        }
        h
    }

    fn status_of(blocked: Option<axum::response::Response>) -> Option<StatusCode> {
        blocked.map(|r| r.status())
    }

    /// Admin token `s3cret`, no metrics token.
    fn configured() -> Credentials {
        Credentials {
            admin: Credential::Configured(AdminToken("s3cret".to_owned())),
            metrics: Credential::Unset,
        }
    }

    /// Metrics token `m3trics` only, no admin credential.
    fn metrics_only() -> Credentials {
        Credentials {
            admin: Credential::Unset,
            metrics: Credential::Configured(MetricsToken("m3trics".to_owned())),
        }
    }

    /// Admin `s3cret` and metrics `m3trics`, each in its own role.
    fn both() -> Credentials {
        Credentials {
            admin: Credential::Configured(AdminToken("s3cret".to_owned())),
            metrics: Credential::Configured(MetricsToken("m3trics".to_owned())),
        }
    }

    fn none() -> Credentials {
        Credentials {
            admin: Credential::Unset,
            metrics: Credential::Unset,
        }
    }

    const ADMIN_BEARER: &str = "Bearer s3cret";
    const METRICS_BEARER: &str = "Bearer m3trics";
    const SURFACES: [Surface; 2] = [Surface::Console, Surface::Metrics];
    const POSTURES: [Posture; 2] = [Posture::Dev, Posture::Production];

    #[test]
    fn auth_mode_explicit_value_wins_over_posture() {
        for posture in POSTURES {
            assert_eq!(
                parse_loopback(RawEnv::Value("token"), posture),
                ConsoleAuthMode::Token
            );
            assert_eq!(
                parse_loopback(RawEnv::Value("  ToKeN "), posture),
                ConsoleAuthMode::Token
            );
            assert_eq!(
                parse_loopback(RawEnv::Value("off"), posture),
                ConsoleAuthMode::Off
            );
            assert_eq!(
                parse_loopback(RawEnv::Value("APP"), posture),
                ConsoleAuthMode::App
            );
        }
        assert_eq!(
            parse_loopback(RawEnv::Absent, Posture::Dev),
            ConsoleAuthMode::DevOpen
        );
        assert_eq!(
            parse_loopback(RawEnv::Value("  "), Posture::Dev),
            ConsoleAuthMode::DevOpen
        );
        assert_eq!(
            parse_loopback(RawEnv::Value(""), Posture::Dev),
            ConsoleAuthMode::DevOpen
        );
        assert_eq!(
            parse_loopback(RawEnv::Absent, Posture::Production),
            ConsoleAuthMode::UnsetProd
        );
        assert_eq!(
            parse_loopback(RawEnv::Value(""), Posture::Production),
            ConsoleAuthMode::UnsetProd
        );
    }

    #[test]
    fn auth_mode_unknown_value_fails_closed() {
        for raw in ["tokne", "open", "dev-open", "none", "true", "1"] {
            for posture in POSTURES {
                assert_eq!(
                    parse_loopback(RawEnv::Value(raw), posture),
                    ConsoleAuthMode::Off,
                    "unknown IPE_CONSOLE_AUTH={raw:?} must resolve to off"
                );
            }
            // Even a request carrying the right token is refused.
            let mode = parse_loopback(RawEnv::Value(raw), Posture::Dev);
            for surface in SURFACES {
                assert_eq!(
                    status_of(gate_decision(
                        mode,
                        surface,
                        &auth_headers(Some(ADMIN_BEARER)),
                        configured
                    )),
                    Some(StatusCode::NOT_FOUND)
                );
            }
        }
    }

    #[test]
    fn auth_mode_non_unicode_value_fails_closed() {
        let read = Err(std::env::VarError::NotUnicode(std::ffi::OsString::new()));
        let raw = RawEnv::from_read(&read);
        assert_eq!(raw, RawEnv::NotUnicode);
        for posture in POSTURES {
            let mode = parse_loopback(raw, posture);
            assert_eq!(
                mode,
                ConsoleAuthMode::Off,
                "non-UTF-8 IPE_CONSOLE_AUTH must resolve to off ({posture:?})"
            );
            assert_eq!(
                status_of(gate_decision(
                    mode,
                    Surface::Console,
                    &auth_headers(Some(ADMIN_BEARER)),
                    configured
                )),
                Some(StatusCode::NOT_FOUND)
            );
        }
    }

    #[test]
    fn explicit_token_enforced_in_dev_posture() {
        let mode = parse_loopback(RawEnv::Value("token"), Posture::Dev);
        for refused in [
            None,
            Some("Bearer wrong"),
            Some("Bearer s3cret "),
            Some("bearer s3cret"),
            Some("s3cret"),
            Some("Basic dXNlcjp3cm9uZw=="),
            Some("Basic !!not-base64!!"),
        ] {
            for surface in SURFACES {
                assert_eq!(
                    status_of(gate_decision(
                        mode,
                        surface,
                        &auth_headers(refused),
                        configured
                    )),
                    Some(StatusCode::UNAUTHORIZED),
                    "dev posture + IPE_CONSOLE_AUTH=token must refuse {refused:?} on {surface:?}"
                );
            }
        }
        for surface in SURFACES {
            assert!(
                gate_decision(mode, surface, &auth_headers(Some(ADMIN_BEARER)), configured)
                    .is_none()
            );
            assert!(
                gate_decision(
                    mode,
                    surface,
                    &auth_headers(Some("Basic dXNlcjpzM2NyZXQ=")),
                    configured
                )
                .is_none()
            );
        }
    }

    #[test]
    fn explicit_token_without_configured_token_refuses_all() {
        let mode = parse_loopback(RawEnv::Value("token"), Posture::Dev);
        for surface in SURFACES {
            for header in [Some("Bearer "), Some(ADMIN_BEARER), None] {
                assert_eq!(
                    status_of(gate_decision(mode, surface, &auth_headers(header), none)),
                    Some(StatusCode::UNAUTHORIZED)
                );
            }
        }
    }

    #[test]
    fn posture_default_applies_only_when_unset() {
        let open = parse_loopback(RawEnv::Absent, Posture::Dev);
        assert!(gate_decision(open, Surface::Console, &auth_headers(None), configured).is_none());
        let prod = parse_loopback(RawEnv::Absent, Posture::Production);
        assert_eq!(
            status_of(gate_decision(
                prod,
                Surface::Console,
                &auth_headers(None),
                configured
            )),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert!(
            gate_decision(
                prod,
                Surface::Console,
                &auth_headers(Some(ADMIN_BEARER)),
                configured
            )
            .is_none()
        );
        assert_eq!(
            status_of(gate_decision(
                ConsoleAuthMode::App,
                Surface::Console,
                &auth_headers(Some(ADMIN_BEARER)),
                configured
            )),
            Some(StatusCode::NOT_IMPLEMENTED)
        );
    }

    #[test]
    fn metrics_token_never_opens_the_console() {
        for mode in [ConsoleAuthMode::Token, ConsoleAuthMode::UnsetProd] {
            for creds in [metrics_only, both] {
                assert_eq!(
                    status_of(gate_decision(
                        mode,
                        Surface::Console,
                        &auth_headers(Some(METRICS_BEARER)),
                        creds
                    )),
                    Some(StatusCode::UNAUTHORIZED),
                    "a metrics credential must be refused on the console"
                );
                assert!(
                    gate_decision(
                        mode,
                        Surface::Metrics,
                        &auth_headers(Some(METRICS_BEARER)),
                        creds
                    )
                    .is_none(),
                    "a metrics credential must be accepted on /_ipe/metrics"
                );
            }
        }
    }

    #[test]
    fn both_tokens_each_accepted_in_its_role() {
        for mode in [ConsoleAuthMode::Token, ConsoleAuthMode::UnsetProd] {
            for surface in SURFACES {
                assert!(
                    gate_decision(mode, surface, &auth_headers(Some(ADMIN_BEARER)), both).is_none(),
                    "the admin credential must be accepted on {surface:?}"
                );
            }
            assert!(
                gate_decision(
                    mode,
                    Surface::Metrics,
                    &auth_headers(Some("Basic cHJvbTptM3RyaWNz")),
                    both
                )
                .is_none(),
                "a Basic metrics credential must be accepted on /_ipe/metrics"
            );
            assert_eq!(
                status_of(gate_decision(
                    mode,
                    Surface::Console,
                    &auth_headers(Some("Basic cHJvbTptM3RyaWNz")),
                    both
                )),
                Some(StatusCode::UNAUTHORIZED)
            );
        }
    }

    #[test]
    fn metrics_only_production_does_not_mount_console() {
        // The mount check keys off the admin chain alone.
        let metrics = Credential::resolve([TokenSource::Set("m3trics".to_owned())], MetricsToken);
        assert!(metrics.is_configured());
        let admin = Credential::resolve([TokenSource::Unset, TokenSource::Unset], AdminToken);
        assert!(!admin.is_configured());
    }

    #[test]
    fn credential_chain_precedence() {
        let first = Credential::resolve(
            [
                TokenSource::Set("high".to_owned()),
                TokenSource::Set("low".to_owned()),
            ],
            AdminToken,
        );
        assert!(first.admits(&Presented("high".to_owned())));
        assert!(!first.admits(&Presented("low".to_owned())));
        let deferred = Credential::resolve(
            [TokenSource::Unset, TokenSource::Set("low".to_owned())],
            AdminToken,
        );
        assert!(deferred.admits(&Presented("low".to_owned())));
        let empty: [TokenSource; 0] = [];
        assert!(matches!(
            Credential::resolve(empty, AdminToken),
            Credential::Unset
        ));
    }

    #[test]
    fn non_unicode_token_source_refuses_the_role() {
        // A garbled higher-precedence token never falls through to a
        // lower-precedence one.
        let admin = Credential::resolve(
            [
                TokenSource::NotUnicode,
                TokenSource::Set("s3cret".to_owned()),
            ],
            AdminToken,
        );
        assert!(matches!(admin, Credential::Unusable));
        assert!(!admin.is_configured());
        assert!(!admin.admits(&Presented("s3cret".to_owned())));
        let creds = || Credentials {
            admin: Credential::resolve(
                [
                    TokenSource::NotUnicode,
                    TokenSource::Set("s3cret".to_owned()),
                ],
                AdminToken,
            ),
            metrics: Credential::Unset,
        };
        for surface in SURFACES {
            assert_eq!(
                status_of(gate_decision(
                    ConsoleAuthMode::Token,
                    surface,
                    &auth_headers(Some(ADMIN_BEARER)),
                    creds
                )),
                Some(StatusCode::UNAUTHORIZED)
            );
        }
    }

    #[test]
    fn surface_of_path() {
        assert_eq!(Surface::of_path("/_ipe/metrics"), Some(Surface::Metrics));
        assert_eq!(Surface::of_path("/_ipe/console"), Some(Surface::Console));
        assert_eq!(
            Surface::of_path("/_ipe/console/api/logs"),
            Some(Surface::Console)
        );
        assert_eq!(Surface::of_path("/_ipe/metrics/x"), None);
        assert_eq!(Surface::of_path("/"), None);
    }

    // Pure (no env dependency) — safe as its own test, no race with
    // ingest_token_gate's IPE_INGEST_TOKEN mutation below.
    #[test]
    fn is_cross_origin_ingest_detection() {
        let mk = |origin: Option<&str>, host: &str| {
            let mut h = axum::http::HeaderMap::new();
            if let Some(o) = origin {
                h.insert("origin", o.parse().unwrap());
            }
            h.insert("host", host.parse().unwrap());
            h
        };
        assert!(is_cross_origin_ingest(&mk(
            Some("https://evil.example"),
            "victim.example"
        )));
        assert!(!is_cross_origin_ingest(&mk(
            Some("https://victim.example"),
            "victim.example"
        )));
        // No Origin header at all → not flagged (curl / server-to-server push).
        assert!(!is_cross_origin_ingest(&mk(None, "victim.example")));
        // An implicit-default-port Origin against an explicit-default-port
        // Host is the SAME origin, not a mismatch.
        assert!(!is_cross_origin_ingest(&mk(
            Some("https://victim.example"),
            "victim.example:443"
        )));
    }

    fn origin_headers(origin: Option<&'static str>) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        if let Some(origin) = origin {
            h.insert("origin", axum::http::HeaderValue::from_static(origin));
            h.insert(
                "host",
                axum::http::HeaderValue::from_static("victim.example"),
            );
        }
        h
    }

    #[test]
    fn ingest_gate_without_token() {
        // A loopback dev build: open when same-origin or Origin-less (curl, a
        // same-process push); a cross-origin browser POST is refused.
        let dev = test_dev_surface();
        assert!(ingest_decision(&origin_headers(None), None, Some(&dev)).is_none());
        assert!(
            ingest_decision(
                &origin_headers(Some("https://victim.example")),
                None,
                Some(&dev)
            )
            .is_none()
        );
        assert_eq!(
            status_of(ingest_decision(
                &origin_headers(Some("https://evil.example")),
                None,
                Some(&dev)
            )),
            Some(StatusCode::FORBIDDEN)
        );
        // Anywhere else (release build, production posture, exposed bind) an
        // Origin-less push needs the token.
        for headers in [
            origin_headers(None),
            origin_headers(Some("https://victim.example")),
        ] {
            assert_eq!(
                status_of(ingest_decision(&headers, None, None)),
                Some(StatusCode::UNAUTHORIZED)
            );
        }
    }

    // `ENV=dev` alone never opens a token-less ingest through the env-driven
    // gate. A Release build fails the build axis even on a recorded loopback
    // listener; a dev-posture build fails the scope axis, since no listener
    // is recorded there.
    #[test]
    fn env_dev_alone_does_not_open_token_less_ingest() {
        crate::system::locked_set_var("ENV", "dev");
        crate::system::locked_remove_var("IPE_INGEST_TOKEN");
        if !cfg!(feature = "dev-posture") {
            crate::telemetry::record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        }
        assert_eq!(
            status_of(ingest_token_blocked(&origin_headers(None))),
            Some(StatusCode::UNAUTHORIZED)
        );
        crate::system::locked_remove_var("ENV");
    }

    // Each axis refuses on its own: with the other two open, a Release build,
    // a production posture, or an exposed listener alone keeps a token-less
    // push out, on every compiled build.
    #[test]
    fn each_closed_axis_alone_refuses_token_less_ingest() {
        let surface = |build, posture, scope| {
            dev_intent(build, posture).and_then(|intent| dev_surface(intent, scope))
        };
        let open = surface(
            BuildPosture::Development,
            Posture::Dev,
            ProcessScope::Loopback,
        );
        assert!(ingest_decision(&origin_headers(None), None, open.as_ref()).is_none());
        for (axis, closed) in [
            (
                "build",
                surface(BuildPosture::Release, Posture::Dev, ProcessScope::Loopback),
            ),
            (
                "posture",
                surface(
                    BuildPosture::Development,
                    Posture::Production,
                    ProcessScope::Loopback,
                ),
            ),
            (
                "scope unbound",
                surface(
                    BuildPosture::Development,
                    Posture::Dev,
                    ProcessScope::Unbound,
                ),
            ),
            (
                "scope exposed",
                surface(
                    BuildPosture::Development,
                    Posture::Dev,
                    ProcessScope::Exposed,
                ),
            ),
        ] {
            assert_eq!(
                status_of(ingest_decision(
                    &origin_headers(None),
                    None,
                    closed.as_ref()
                )),
                Some(StatusCode::UNAUTHORIZED),
                "{axis} axis"
            );
        }
    }

    #[test]
    fn ingest_gate_with_token() {
        let surface = test_dev_surface();
        for dev in [Some(&surface), None] {
            let want = Some("secret123");
            assert!(
                ingest_decision(&origin_headers(None), want, dev).is_some(),
                "missing header blocked"
            );
            let mut h = axum::http::HeaderMap::new();
            h.insert("x-ipe-ingest-token", "wrong".parse().unwrap());
            assert!(
                ingest_decision(&h, want, dev).is_some(),
                "wrong token blocked"
            );
            // Correct token → allowed, even cross-origin (bearer-token auth
            // makes the same-origin check redundant).
            let mut h = origin_headers(Some("https://evil.example"));
            h.insert("x-ipe-ingest-token", "secret123".parse().unwrap());
            assert!(
                ingest_decision(&h, want, dev).is_none(),
                "correct token allowed even cross-origin"
            );
        }
    }

    #[test]
    fn ingest_escapes_every_log_hazard_visibly() {
        assert_eq!(
            sanitise_ingest("a\u{2028}b\u{200B}c\u{E0041}d"),
            "a\\u{2028}b\\u{200b}c\\u{e0041}d"
        );
        assert_ne!(sanitise_ingest("adm\u{200B}in"), sanitise_ingest("admin"));
        let long = sanitise_ingest(&"\u{1b}".repeat(4096));
        assert!(
            long.len() <= 8192 + crate::system::SCRUB_TRUNCATED.len(),
            "{}",
            long.len()
        );
        assert!(long.ends_with(crate::system::SCRUB_TRUNCATED), "{long:?}");
    }
}

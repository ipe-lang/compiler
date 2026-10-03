//! Ipe.Web observability endpoints — the operator surface mounted on every
//! Web app, mirroring  ``:
//!
//! - `GET /_ipe/healthz`  — liveness probe, always `{"status":"ok"}`.
//! - `GET /_ipe/readyz`   — readiness probe, `{"status":"ready"}` (200) or
//!   `{"status":"draining"}` (503) once shutdown is signalled.
//! - `GET /_ipe/buildinfo`— commit / builtAt / ipeVersion JSON.
//! - `GET /_ipe/metrics`  — Prometheus text: `ipe_web_requests_total`.
//!
//! Requests are counted by the `track` middleware layer. No panic vectors: every
//! handler returns a static or counter-derived body; nothing can fail.
//!
//! Out of scope here (staged for the console mini-app port): `/_ipe/console/*`
//! (the Ipe.Ui dashboard), `/_ipe/observability/ingest` (sub-app federation), and
//! the in-RAM log/span ring buffers the console renders.

use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use std::sync::atomic::{AtomicBool, Ordering};

/// Readiness flag. Starts ready; a graceful-shutdown signal flips it so
/// `/_ipe/readyz` reports `draining` and load balancers stop routing new traffic
/// while in-flight requests finish .
static READY: AtomicBool = AtomicBool::new(true);

/// Flip readiness to draining (call from a shutdown handler). Idempotent.
pub fn mark_draining() {
    READY.store(false, Ordering::SeqCst);
}

const JSON: (header::HeaderName, &str) = (header::CONTENT_TYPE, "application/json");

/// `GET /_ipe/healthz` — liveness. Always OK while the process is up.
pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, [JSON], r#"{"status":"ok"}"#)
}

/// `GET /_ipe/readyz` — readiness. 200 `ready`, or 503 `draining` once shutdown
/// is signalled.
pub async fn readyz() -> impl IntoResponse {
    if READY.load(Ordering::SeqCst) {
        (StatusCode::OK, [JSON], r#"{"status":"ready"}"#)
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [JSON],
            r#"{"status":"draining"}"#,
        )
    }
}

/// `GET /_ipe/buildinfo` — build provenance. Values come from compile-time env
/// (`IPE_BUILD_COMMIT` / `IPE_BUILD_AT` / `IPE_VERSION`), defaulting to `dev`.
pub async fn buildinfo() -> impl IntoResponse {
    let commit = option_env!("IPE_BUILD_COMMIT").unwrap_or("dev");
    let built_at = option_env!("IPE_BUILD_AT").unwrap_or("unknown");
    let version = option_env!("IPE_VERSION").unwrap_or("dev");
    let body =
        format!(r#"{{"commit":"{commit}","builtAt":"{built_at}","ipeVersion":"{version}"}}"#);
    (StatusCode::OK, [JSON], body)
}

/// `GET /_ipe/metrics` — full Prometheus 0.0.4 text exposition.
pub async fn metrics() -> impl IntoResponse {
    // The whole exposition comes from the labeled registry — active sessions,
    // SSE connections, 5xx errors,
    // request-latency histogram, AND `ipe_web_requests_total{method,status}`
    // written per request by the `track` middleware below. `write_prom` emits
    // exactly one #HELP/#TYPE per metric name, so there is NO hand-printed
    // unlabeled `ipe_web_requests_total` line here: a second, unlabeled series
    // under the same name would mean a duplicate #HELP/#TYPE block, which makes
    // a Prometheus scraper reject the entire exposition.
    let body = crate::telemetry::write_prom();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
}

/// axum middleware: per-request observability (— its access-log +
/// OTel-span middleware wraps the whole mux). Counts every request, and for
/// user-facing requests auto-records a span + an access log so the console has
/// data without the app calling `Ipe.Trace`/`Ipe.Log` itself.
pub async fn track(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Gate the console + metrics surface (off / production-auth) before serving.
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    if let Some(surface) = super::console::Surface::of_path(&path)
        && let Some(blocked) = super::console::gate_blocked(surface, req.headers())
    {
        super::super::telemetry::record_request(blocked.status().as_u16());
        return blocked;
    }
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    // Feed the Ipê Console telemetry (request count + 5xx error count).
    super::super::telemetry::record_request(status);
    // Auto request span + access log — but NOT for the internal observability
    // surface (SSE long-poll → multi-minute span; console proxy / metrics /
    // health → console's own polling noise) and NOT for a sub-app. A sub-app
    // (`IPE_WEB_BASE_PATH` set — e.g. the console child collector) must not
    // self-instrument into the store it serves; it shows the PARENT's pushed
    // telemetry, not its own page renders.
    if !is_internal_path(&path) && !is_sub_app() {
        let dur_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
        // Request-latency histogram .
        // UNLABELED on purpose — labeling by the raw path would be an unbounded-
        // cardinality memory-DoS (the registry never evicts); labels by a
        // bounded route template, which the Rust middleware doesn't have here.
        super::super::telemetry::metric_observe(
            "ipe_web_request_seconds",
            &[],
            dur_us as f64 / 1_000_000.0,
        );
        // Labeled request counter
        // (`ipe_web_requests_total{method,route,status}`). We keep two
        // BOUNDED labels — `method` normalised to a closed set, and the full
        // numeric `status` (bounded by the HTTP spec) — but DROP  `route`
        // label: it is derived from the raw request path, an attacker-
        // controllable, UNBOUNDED value, and the registry never evicts (the
        // classic Prometheus cardinality memory-DoS). The histogram above drops
        // its label for the same reason. `method` is itself bounded here because
        // HTTP permits arbitrary extension-method tokens.
        let status_str = status.to_string();
        super::super::telemetry::metric_inc(
            "ipe_web_requests_total",
            &[
                ("method", normalize_method(&method)),
                ("status", &status_str),
            ],
            1,
        );
        let ok = status < 500;
        // The attacker-controllable raw path enters the in-RAM log ring / OTLP
        // push only escaped and capped (see `sanitise_path`).
        let safe_path = sanitise_path(&path);
        super::super::telemetry::record_span(&format!("{method} {safe_path}"), dur_us, ok);
        let level = if status >= 500 { "error" } else { "info" };
        super::super::telemetry::record_log(
            level,
            &format!("{method} {safe_path} -> {status} ({}ms)", dur_us / 1000),
        );
    }
    resp
}

/// Map an HTTP method token to one of a CLOSED set of labels, so the
/// `ipe_web_requests_total{method=…}` series can never explode in cardinality.
/// HTTP permits arbitrary extension-method tokens and `req.method()` preserves
/// the on-wire bytes verbatim, so without this an attacker could mint an
/// unbounded number of distinct `method` label values against a registry that
/// never evicts (a memory-DoS). Only the RFC-canonical UPPER-CASE spellings
/// match; any case-variant (`get`/`Get`) or non-standard token deliberately
/// buckets to `"other"` — a non-conformant client is not worth a distinct
/// series, and bounded cardinality outranks label fidelity. Returns a
/// `&'static str` so the labelling path stays zero-allocation (no `to_uppercase`
/// — case-folding would allocate per request for zero cardinality benefit, since
/// every variant already collapses to one arm here).
fn normalize_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "CONNECT" => "CONNECT",
        _ => "other",
    }
}

/// The request path as recorded into the telemetry rings / federation push.
///
/// The path is remote-supplied and otherwise unbounded, a log-injection,
/// record-spoofing and memory-amplification vector. Every log hazard
/// (`crate::system::is_log_hazard`, Unicode `Cc ∪ Cf ∪ Zl ∪ Zp`) becomes a
/// visible escape rather than vanishing, so `/adm<U+200B>in` can never record as
/// `/admin`, and the escaped form is capped at 256 bytes.
fn sanitise_path(path: &str) -> String {
    const MAX_PATH_BYTES: usize = 256;
    crate::system::scrub_log_controls_capped(path, MAX_PATH_BYTES)
}

/// Internal observability/transport paths that must NOT be auto-instrumented:
/// the SSE long-poll (a multi-minute span), the console reverse-proxy + its
/// events (the console's own traffic), and the health/metrics/build/ingest
/// endpoints (operator polling noise).
/// True when this process runs as a sub-app (mounted behind a parent's proxy,
/// `IPE_WEB_BASE_PATH` non-empty) — e.g. the bundled console child. Fixed for
/// the process lifetime (set once at spawn by the parent's `MountSubApp`), so
/// the env read is memoized: `track` runs this on every user-facing request,
/// and `env::var` both locks the process-global env mutex and heap-allocates a
/// `String` per call.
fn is_sub_app() -> bool {
    static SUB_APP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUB_APP.get_or_init(|| {
        crate::system::read_env_var("IPE_WEB_BASE_PATH")
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    })
}

fn is_internal_path(path: &str) -> bool {
    path == "/_ipe/sse"
        || path == "/_ipe/event"
        || path == "/_ipe/metrics"
        || path == "/_ipe/healthz"
        || path == "/_ipe/readyz"
        || path == "/_ipe/buildinfo"
        || path == "/_ipe/observability/ingest"
        || path.starts_with("/_ipe/console")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    async fn body_string(r: axum::response::Response) -> String {
        let bytes = to_bytes(r.into_body(), 64 * 1024).await.unwrap_or_default();
        String::from_utf8(bytes.to_vec()).unwrap_or_default()
    }

    #[test]
    fn sanitise_path_escapes_every_log_hazard_visibly() {
        assert_eq!(
            sanitise_path("/a\u{202E}b\u{200B}c\u{E0041}d\u{2028}e\u{1B}[31mf\n"),
            "/a\\u{202e}b\\u{200b}c\\u{e0041}d\\u{2028}e\\u{1b}[31mf\\n"
        );
        // A hidden character never lets one path record as another.
        assert_ne!(sanitise_path("/adm\u{200B}in"), sanitise_path("/admin"));
        assert_eq!(sanitise_path("/admin"), "/admin");
        // The cap bounds the escaped form, not the raw path.
        let long = sanitise_path(&format!("/{}", "\u{202E}".repeat(200)));
        assert!(
            long.len() <= 256 + crate::system::SCRUB_TRUNCATED.len(),
            "{}",
            long.len()
        );
        assert!(long.ends_with(crate::system::SCRUB_TRUNCATED), "{long:?}");
    }

    #[test]
    fn internal_paths_are_not_auto_instrumented() {
        // SSE long-poll, event transport, console proxy, ops endpoints → skipped.
        assert!(super::is_internal_path("/_ipe/sse"));
        assert!(super::is_internal_path("/_ipe/event"));
        assert!(super::is_internal_path("/_ipe/console"));
        assert!(super::is_internal_path("/_ipe/console/_ipe/sse"));
        assert!(super::is_internal_path("/_ipe/healthz"));
        // User-facing routes → instrumented.
        assert!(!super::is_internal_path("/"));
        assert!(!super::is_internal_path("/api/users"));
        assert!(!super::is_internal_path("/dashboard"));
    }

    #[tokio::test]
    async fn healthz_ok() {
        let r = healthz().await.into_response();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(body_string(r).await, r#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn buildinfo_is_json_with_fields() {
        let r = buildinfo().await.into_response();
        assert_eq!(r.status(), StatusCode::OK);
        let b = body_string(r).await;
        assert!(b.contains("\"commit\""), "{b}");
        assert!(b.contains("\"ipeVersion\""), "{b}");
    }

    #[tokio::test]
    async fn metrics_exposes_counter() {
        // The registry is empty until the first inc (
        // metrics test Incs first); the `track` middleware writes this series
        // per request. Seed one labeled series, then assert the name + its
        // bounded labels appear. Substring-only assertions keep this
        // order-independent against the process-global registry.
        crate::telemetry::metric_inc(
            "ipe_web_requests_total",
            &[("method", "GET"), ("status", "200")],
            1,
        );
        let r = metrics().await.into_response();
        assert_eq!(r.status(), StatusCode::OK);
        let b = body_string(r).await;
        assert!(b.contains("ipe_web_requests_total"), "{b}");
        assert!(b.contains("method=\"GET\""), "{b}");
        assert!(b.contains("status=\"200\""), "{b}");
    }

    #[test]
    fn normalize_method_buckets_unknown_and_case_variants() {
        // Canonical methods pass through verbatim.
        assert_eq!(super::normalize_method("GET"), "GET");
        assert_eq!(super::normalize_method("POST"), "POST");
        assert_eq!(super::normalize_method("CONNECT"), "CONNECT");
        // Case variants of a known method are non-canonical → bucketed.
        assert_eq!(super::normalize_method("get"), "other");
        assert_eq!(super::normalize_method("Get"), "other");
        // Arbitrary extension-method token / empty → bucketed (cardinality guard).
        assert_eq!(super::normalize_method("FOOBAR"), "other");
        assert_eq!(super::normalize_method(""), "other");
    }

    // Regression: a panicking handler must become a 500 (not an unwound, dropped
    // connection) AND still be counted by `track` as status 500 — the
    // contract for the new `CatchPanicLayer` placed INNER of `track` in the
    // Ipe.Web router. Well-typed Ipê can't panic (the no-panic thesis), so this
    // defense-in-depth floor can only be exercised from a test handler that
    // deliberately panics. NOTE: `.unwrap()`/`.expect()` are denied on ALL
    // targets (incl. tests); `panic!` and `match Infallible {}` are the allowed
    // totals here.
    #[tokio::test]
    async fn handler_panic_becomes_500_and_is_counted() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt; // oneshot

        // Test-only handler that deliberately panics — the behaviour under test
        // (what `CatchPanicLayer` must convert to a 500). Explicit `-> Response`
        // return so the never type doesn't trip the denied
        // `dependency_on_unit_never_type_fallback` lint; `#[cfg(test)]` marks it
        // as genuine test code for the risk-lint precheck.
        // The panic message embeds a FAKE SECRET — the no-leak assertion below
        // proves it never reaches the client (it goes to the server log only).
        #[cfg(test)]
        async fn boom() -> axum::response::Response {
            panic!("token=SECRET123 internal /etc/secret leaked")
        }

        // Mirror the real Ipe.Web nesting: track( catch_panic( handler ) ) with
        // the REAL shared responder. csrf is omitted — it only acts on mutating
        // methods, so a GET panic exercises the catch_panic→500 path + track's
        // post-`next.run` metering identically.
        let app = Router::new()
            .route("/boom", get(boom))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(
                |err: Box<dyn std::any::Any + Send + 'static>| {
                    use axum::response::IntoResponse;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        crate::core::panic_500_body(&*err),
                    )
                        .into_response()
                },
            ))
            .layer(axum::middleware::from_fn(track));

        let req = match Request::builder().uri("/boom").body(Body::empty()) {
            Ok(r) => r,
            Err(e) => panic!("build request: {e}"),
        };
        // Router's Service error is `Infallible`; `match e {}` is total.
        let resp = app.oneshot(req).await.unwrap_or_else(|e| match e {});
        // Panic was caught and converted, not propagated.
        let status = resp.status();
        let body = body_string(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // SECURITY (the load-bearing invariant): the 500 body carries ONLY the
        // errId — the panic message (here a fake secret) must NEVER reach the
        // client.
        assert!(
            body.contains("ref"),
            "expected an errId `ref` in the body: {body}"
        );
        assert!(
            !body.contains("SECRET123") && !body.contains("/etc/secret"),
            "panic message LEAKED into the 500 response body: {body}"
        );
        // the converted 500 returns through `track` normally, so the
        // request is counted with status="500" (not skipped via an unwind).
        let m = crate::telemetry::write_prom();
        assert!(m.contains("ipe_web_requests_total"), "{m}");
        assert!(m.contains("status=\"500\""), "{m}");
    }

    // Request isolation for a recursion trip: a handler whose panic is the
    // recursion-guard trip (`maximum recursion depth exceeded`) is contained by
    // the SAME `CatchPanicLayer` — that request gets a 500 carrying only the
    // errId, a CONCURRENT healthy route completes normally, and a request AFTER
    // the trip is still served. The listener (here the shared router service)
    // survives the runaway recursion; only the one request is lost. The 500 body
    // never carries the trip message. This is the runtime half of the Ipe.Http.Server
    // isolation contract the emitted handler rides.
    #[tokio::test]
    async fn recursion_trip_in_handler_is_isolated_per_request() {
        use axum::Router;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::get;
        use tower::ServiceExt; // oneshot

        // A handler that trips the recursion guard: it panics with the exact
        // fixed message `recursion_guard()` raises. Explicit `-> Response` so the
        // never type doesn't trip the denied never-type-fallback lint.
        #[cfg(test)]
        async fn runaway() -> axum::response::Response {
            let _g = crate::core::recursion_guard();
            // Drive the guard to a trip directly rather than actually recursing
            // 10 000 frames in a unit test: raise the same fixed message the guard
            // raises, so this exercises the classify→500 containment path a real
            // trip takes.
            panic!("maximum recursion depth exceeded")
        }
        #[cfg(test)]
        async fn healthy() -> axum::response::Response {
            use axum::response::IntoResponse;
            (StatusCode::OK, "ok").into_response()
        }

        let app = Router::new()
            .route("/runaway", get(runaway))
            .route("/healthy", get(healthy))
            .layer(tower_http::catch_panic::CatchPanicLayer::custom(
                |err: Box<dyn std::any::Any + Send + 'static>| {
                    use axum::response::IntoResponse;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [(axum::http::header::CONTENT_TYPE, "application/json")],
                        crate::core::panic_500_body(&*err),
                    )
                        .into_response()
                },
            ))
            .layer(axum::middleware::from_fn(track));

        let call = |path: &'static str| {
            let app = app.clone();
            async move {
                let req = match Request::builder().uri(path).body(Body::empty()) {
                    Ok(r) => r,
                    Err(e) => panic!("build request: {e}"),
                };
                let resp = app.oneshot(req).await.unwrap_or_else(|e| match e {});
                let status = resp.status();
                let body = body_string(resp).await;
                (status, body)
            }
        };

        // Request A (runaway) and request B (healthy) run concurrently; A must be
        // contained without taking B down with it.
        let (a, b) = tokio::join!(call("/runaway"), call("/healthy"));
        let (a_status, a_body) = a;
        let (b_status, _b_body) = b;

        assert_eq!(
            a_status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the tripped handler returns a 500"
        );
        assert!(
            a_body.contains("ref"),
            "the 500 carries a correlation ref: {a_body}"
        );
        assert!(
            !a_body.contains("maximum recursion depth exceeded"),
            "the trip message must NEVER reach the client: {a_body}"
        );
        assert_eq!(
            b_status,
            StatusCode::OK,
            "a concurrent healthy request completes normally"
        );

        // Request C after the trip: the service is still alive and serving.
        let (c_status, _c_body) = call("/healthy").await;
        assert_eq!(
            c_status,
            StatusCode::OK,
            "a request after the trip is still served — the listener survives"
        );
    }

    #[tokio::test]
    async fn readyz_flips_to_draining() {
        // Default ready.
        let r = readyz().await.into_response();
        assert_eq!(r.status(), StatusCode::OK);
        mark_draining();
        let r2 = readyz().await.into_response();
        assert_eq!(r2.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(body_string(r2).await.contains("draining"));
        // Restore for any other test ordering (process-global flag).
        READY.store(true, Ordering::SeqCst);
    }
}

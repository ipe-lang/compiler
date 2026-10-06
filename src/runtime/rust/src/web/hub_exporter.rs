//! Remote hub OTLP push — HubExporter.
//!
//! When `IPE_CONSOLE_HUB` is set, this background exporter batches logs + spans
//! and pushes them as **OTLP/JSON** to a remote `ipe console-serve` hub
//! (`POST <hub>/v1/logs`, `POST <hub>/v1/traces`, `Content-Type:
//! application/json`), bearer-authenticated via `IPE_CONSOLE_HUB_TOKEN`. A
//! batch that fails to push is kept in a bounded in-memory **spool** and retried
//! on the next tick, so a transient hub outage never drops telemetry on the
//! floor; transient hub outages never drop telemetry.
//!
//! OTLP/JSON over HTTP (the protobuf field names as JSON keys); no protobuf
//! dependency required.
//!
//! Spool backend: in-memory (bounded) — covers transient outages + retry.
//! File-spool restart-durability (`IPE_CONSOLE_SPOOL_MODE=file`,
//! env knobs `IPE_CONSOLE_SPOOL_*`) is not yet implemented; those env
//! knobs are not read.
//!
//! `live`-gated. Best-effort, no panic vectors: bounded offer queue (drop on
//! full), push failures fall back to the spool, the spool itself is bounded
//! (oldest batch evicted when full). No `unwrap`/`expect`/indexing.

use super::push_exporter::{
    ExporterEnv, FlushDeadline, OutcomeLog, PushOutcome, drain_before_exit,
};
use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const DEFAULT_QUEUE_CAP: usize = 1024;
const DEFAULT_INTERVAL_MS: u64 = 2000;
const MIN_INTERVAL_MS: u64 = 100;
const MIN_TOKEN_BYTES: usize = 32;
/// Max batches held in the retry spool before the oldest is evicted.
const SPOOL_MAX_BATCHES: usize = 256;
/// Total bytes of spooled batch JSON before the oldest is evicted
/// (`IPE_CONSOLE_SPOOL_MAX_BYTES` default 100 MB). Bounds the spool by size
/// as well as by batch count — a single batch can be large.
const SPOOL_MAX_BYTES: usize = 100 * 1024 * 1024;
/// Max accumulated entries (logs + spans) held between flushes before an early
/// flush is forced. Bounds the in-memory accumulator by count rather than only
/// by the flush interval — a high-rate producer can otherwise grow it without
/// bound (the channel stays near-empty as the batcher drains it eagerly).
const MAX_BATCH_ENTRIES: usize = 4096;

/// One telemetry record queued for the exporter.
pub(crate) enum Entry {
    Log {
        ts_ms: u64,
        level: String,
        message: String,
    },
    Span {
        ts_ms: u64,
        name: String,
        dur_us: u64,
        ok: bool,
    },
    /// Synchronous flush request: batcher drains its buffer then acks via the
    /// oneshot. Used by `flush_now` for a bounded pre-exit drain.
    Flush(tokio::sync::oneshot::Sender<()>),
}

static SENDER: OnceLock<mpsc::Sender<Entry>> = OnceLock::new();

/// Enable the remote-hub OTLP exporter from env. No-op unless `IPE_CONSOLE_HUB`
/// is set. Refuses a too-short token (< 32 bytes). Idempotent; call once at boot.
pub async fn enable_from_env() {
    // Trim ONCE so the URL we validate is the exact one we push to. A
    // leading-whitespace value (" https://hub") otherwise passes the scheme
    // check (which trims) yet leaves the space in `base`, so every push fails
    // with an invalid URL.
    let hub = match ExporterEnv::HubUrl.read() {
        Some(h) if !h.trim().is_empty() => h.trim().to_string(),
        _ => return,
    };
    if SENDER.get().is_some() {
        return;
    }
    let token = ExporterEnv::HubToken.read().unwrap_or_default();
    if token.len() < MIN_TOKEN_BYTES {
        crate::system::emit_runtime_log(
            "hub",
            &format!(
                "{} must be ≥{MIN_TOKEN_BYTES} bytes to push to {}; exporter disabled",
                ExporterEnv::HubToken.name(),
                super::push_exporter::redacted_origin(&hub)
            ),
        );
        return;
    }
    // Secrets-in-transit: refuse to push a bearer token over cleartext HTTP.
    // A misconfigured `http://` hub URL would leak the ≥32-byte token on the
    // wire. Allow a non-https scheme only when no token is set (anonymous push).
    // PARSE the URL — a string prefix `http://localhost` ALSO matches
    // `http://localhost.evil.com`, leaking the bearer token over cleartext to an
    // attacker host. Accept https://, or http:// ONLY when the host is exactly a
    // loopback name/address.
    if !super::push_exporter::url_allows_cleartext_token(&hub) {
        crate::system::emit_runtime_log(
            "hub",
            &format!(
                "refusing to push bearer token over non-https {}={}; \
                 use https:// (or a localhost loopback); exporter disabled",
                ExporterEnv::HubUrl.name(),
                super::push_exporter::redacted_origin(&hub)
            ),
        );
        return;
    }
    let interval_ms: u64 = match ExporterEnv::HubInterval
        .read_ceiling::<u64>(DEFAULT_INTERVAL_MS, "decimal millisecond count")
    {
        Ok(ms) => ms.max(MIN_INTERVAL_MS),
        Err(refusal) => return super::push_exporter::log_refused_ceiling("hub", &refusal),
    };
    let service = match ExporterEnv::ServiceName.read() {
        Some(s) if !s.is_empty() => s,
        _ => "app".to_string(),
    };
    let base = hub.trim_end_matches('/').to_string();
    let Some(client) = exporter_client(&base) else {
        crate::system::emit_runtime_log("hub", "no HTTP client available; exporter disabled");
        return;
    };

    let (tx, rx) = mpsc::channel::<Entry>(DEFAULT_QUEUE_CAP);
    if SENDER.set(tx).is_err() {
        return;
    }
    crate::system::emit_runtime_log(
        "hub",
        &format!(
            "OTLP push → {}/v1/{{logs,traces}} every {interval_ms}ms",
            super::push_exporter::redacted_origin(&base)
        ),
    );
    tokio::spawn(batcher(
        rx,
        HubTarget {
            client,
            base,
            token,
            service,
        },
        interval_ms,
    ));
}

/// A ready-to-push OTLP/JSON payload for one signal endpoint.
#[derive(Clone)]
struct OtlpBatch {
    path: &'static str, // "/v1/logs" | "/v1/traces"
    json: String,
}

/// Where and as whom the exporter pushes.
struct HubTarget {
    client: reqwest::Client,
    base: String,
    token: String,
    service: String,
}

/// The exporter's reqwest client for the hub at `base`: bounded push/connect
/// timeouts (a hung hub can't wedge the task), the
/// [`super::push_exporter::proxy_route`] for the hub, AND
/// `redirect::Policy::none()`. Following a redirect is
/// a secret-leak vector — reqwest's default follows up to 10 hops and RETAINS
/// the `Authorization` bearer across a same-host `https→http` scheme-downgrade
/// redirect, defeating the https-only enable gate and pushing the token over
/// cleartext. A machine-to-machine exporter POSTs to its configured endpoint; it
/// must never chase a 3xx to an attacker-chosen location. `None` when the TLS
/// backend cannot initialise; there is no unpinned fallback client.
fn exporter_client(base: &str) -> Option<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::none());
    super::push_exporter::routed(builder, base).build().ok()
}

/// Accumulate entries; on each tick encode + push, retrying spooled batches
/// first. Channel close drains a final flush. A `Flush` sentinel drains
/// immediately and acks.
async fn batcher(mut rx: mpsc::Receiver<Entry>, target: HubTarget, interval_ms: u64) {
    let mut log = OutcomeLog::new(Instant::now());
    let mut logs: Vec<(u64, String, String)> = Vec::new();
    let mut spans: Vec<(u64, String, u64, bool)> = Vec::new();
    let mut spool: VecDeque<OtlpBatch> = VecDeque::new();
    let mut tick = tokio::time::interval(Duration::from_millis(interval_ms));
    tick.tick().await; // skip the immediate first tick
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(Entry::Flush(ack)) => {
                    flush(&target, &mut logs, &mut spans, &mut spool, &mut log).await;
                    // Best-effort ack — ignore send errors (caller may have timed out).
                    let _ = ack.send(());
                }
                Some(Entry::Log { ts_ms, level, message }) => {
                    logs.push((ts_ms, level, message));
                    if logs.len() + spans.len() >= MAX_BATCH_ENTRIES {
                        flush(&target, &mut logs, &mut spans, &mut spool, &mut log).await;
                    }
                }
                Some(Entry::Span { ts_ms, name, dur_us, ok }) => {
                    spans.push((ts_ms, name, dur_us, ok));
                    if logs.len() + spans.len() >= MAX_BATCH_ENTRIES {
                        flush(&target, &mut logs, &mut spans, &mut spool, &mut log).await;
                    }
                }
                None => {
                    flush(&target, &mut logs, &mut spans, &mut spool, &mut log).await;
                    break;
                }
            },
            _ = tick.tick() => {
                flush(&target, &mut logs, &mut spans, &mut spool, &mut log).await;
            }
        }
    }
}

/// Connect ceiling of the hub client, in milliseconds.
///
/// The client builder and `FLUSH_DEADLINE` both read it, so the shutdown
/// flush always outlasts a connect in flight.
const CONNECT_TIMEOUT_MS: u64 = 5_000;

/// How long the shutdown flush waits for the hub batcher's buffer and spool.
const FLUSH_DEADLINE: FlushDeadline = FlushDeadline::after_connect::<CONNECT_TIMEOUT_MS>();

/// Best-effort pre-exit flush of the hub exporter, bounded by `FLUSH_DEADLINE`.
///
/// No-op when the exporter is disabled. Never panics.
pub async fn flush_now() {
    drain_before_exit(SENDER.get(), Entry::Flush, FLUSH_DEADLINE).await;
}

/// Encode the accumulated logs/spans into OTLP batches, then push the spool
/// (oldest first) + the new batches. The first failed push puts it and every
/// batch after it back in the spool, in order, untried (bounded — oldest
/// evicted on overflow); each outcome is reported through `log`.
async fn flush(
    target: &HubTarget,
    logs: &mut Vec<(u64, String, String)>,
    spans: &mut Vec<(u64, String, u64, bool)>,
    spool: &mut VecDeque<OtlpBatch>,
    log: &mut OutcomeLog,
) {
    let service = target.service.as_str();
    if !logs.is_empty() {
        spool_push(
            spool,
            OtlpBatch {
                path: "/v1/logs",
                json: otlp_logs_json(service, logs),
            },
        );
        logs.clear();
    }
    if !spans.is_empty() {
        spool_push(
            spool,
            OtlpBatch {
                path: "/v1/traces",
                json: otlp_spans_json(service, spans),
            },
        );
        spans.clear();
    }
    // Drain the spool in order; the first failure re-spools the rest untried.
    let mut pending: VecDeque<OtlpBatch> = std::mem::take(spool);
    while let Some(batch) = pending.pop_front() {
        let url = format!("{}{}", target.base, batch.path);
        let outcome = push_one(target, &url, &batch).await;
        if let Some(line) = log.observe(Instant::now(), &url, &outcome, &failure_note(batch.path)) {
            crate::system::emit_runtime_log("hub", &line);
        }
        if !matches!(outcome, PushOutcome::Accepted) {
            spool_push(spool, batch);
            while let Some(rest) = pending.pop_front() {
                spool_push(spool, rest);
            }
        }
    }
}

/// Push one OTLP batch to `url` with the bearer: only a 2xx is an acceptance.
async fn push_one(target: &HubTarget, url: &str, batch: &OtlpBatch) -> PushOutcome {
    let req = target
        .client
        .post(url)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", target.token))
        .body(batch.json.clone());
    super::push_exporter::send_classified(req).await
}

/// What becomes of a batch whose push to the OTLP `path` failed. Names the
/// path only, never the bearer.
fn failure_note(path: &str) -> String {
    format!("{path} batch and the batches after it re-spooled")
}

/// Bounded spool insert (evict oldest on overflow — never grows unbounded).
/// Caps BOTH the batch count and the total JSON byte size, since a single batch
/// can be large.
fn spool_push(spool: &mut VecDeque<OtlpBatch>, batch: OtlpBatch) {
    if spool.len() >= SPOOL_MAX_BATCHES {
        spool.pop_front();
    }
    spool.push_back(batch);
    // Byte cap: evict oldest until under the limit, but always keep at least the
    // batch we just pushed (a single oversized batch is preferable to losing it).
    let mut total: usize = spool.iter().map(|b| b.json.len()).sum();
    while total > SPOOL_MAX_BYTES && spool.len() > 1 {
        match spool.pop_front() {
            Some(b) => total = total.saturating_sub(b.json.len()),
            None => break,
        }
    }
}

fn ns(ts_ms: u64) -> String {
    (ts_ms as u128 * 1_000_000).to_string()
}

/// Minimal valid OTLP/JSON ResourceLogs payload.
fn otlp_logs_json(service: &str, logs: &[(u64, String, String)]) -> String {
    let records: Vec<serde_json::Value> = logs
        .iter()
        .map(|(ts, level, msg)| {
            serde_json::json!({
                "timeUnixNano": ns(*ts),
                "severityText": level,
                "body": { "stringValue": msg },
            })
        })
        .collect();
    serde_json::json!({
        "resourceLogs": [{
            "resource": { "attributes": [service_attr(service)] },
            "scopeLogs": [{ "scope": { "name": "ipe" }, "logRecords": records }],
        }]
    })
    .to_string()
}

/// Minimal valid OTLP/JSON ResourceSpans payload. `ok` → status code 1 (OK),
/// else 2 (ERROR) per the OTLP status-code enum.
fn otlp_spans_json(service: &str, spans: &[(u64, String, u64, bool)]) -> String {
    let records: Vec<serde_json::Value> = spans
        .iter()
        .map(|(ts, name, dur_us, ok)| {
            let start = *ts as u128 * 1_000_000;
            let end = start + (*dur_us as u128) * 1_000;
            serde_json::json!({
                "name": name,
                "startTimeUnixNano": start.to_string(),
                "endTimeUnixNano": end.to_string(),
                "status": { "code": if *ok { 1 } else { 2 } },
            })
        })
        .collect();
    serde_json::json!({
        "resourceSpans": [{
            "resource": { "attributes": [service_attr(service)] },
            "scopeSpans": [{ "scope": { "name": "ipe" }, "spans": records }],
        }]
    })
    .to_string()
}

fn service_attr(service: &str) -> serde_json::Value {
    serde_json::json!({ "key": "service.name", "value": { "stringValue": service } })
}

/// Non-blocking offer of a log. No-op when disabled or the queue is full.
pub fn offer_log(ts_ms: u64, level: &str, message: &str) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(Entry::Log {
            ts_ms,
            level: level.to_string(),
            message: message.to_string(),
        });
    }
}

/// Non-blocking offer of a span.
pub fn offer_span(ts_ms: u64, name: &str, dur_us: u64, ok: bool) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(Entry::Span {
            ts_ms,
            name: name.to_string(),
            dur_us,
            ok,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_without_enable_is_noop() {
        offer_log(0, "info", "ignored");
        offer_span(0, "noop", 0, true);
    }

    #[test]
    fn otlp_logs_shape_is_valid() {
        let body = otlp_logs_json("svc", &[(1_700_000_000_000, "error".into(), "boom".into())]);
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(
            v["resourceLogs"][0]["resource"]["attributes"][0]["key"],
            "service.name"
        );
        assert_eq!(
            v["resourceLogs"][0]["resource"]["attributes"][0]["value"]["stringValue"],
            "svc"
        );
        let rec = &v["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(rec["severityText"], "error");
        assert_eq!(rec["body"]["stringValue"], "boom");
        // ts in ns = ms * 1e6
        assert_eq!(rec["timeUnixNano"], "1700000000000000000");
    }

    #[test]
    fn otlp_spans_shape_and_status() {
        let body = otlp_spans_json(
            "svc",
            &[(1_700_000_000_000, "db.query".into(), 5000, false)],
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        let rec = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(rec["name"], "db.query");
        assert_eq!(rec["status"]["code"], 2); // not ok → ERROR
        // end = start + 5000us(5ms) → +5_000_000 ns
        assert_eq!(rec["startTimeUnixNano"], "1700000000000000000");
        assert_eq!(rec["endTimeUnixNano"], "1700000000005000000");
    }

    #[test]
    fn spool_is_bounded() {
        let mut s: VecDeque<OtlpBatch> = VecDeque::new();
        for i in 0..(SPOOL_MAX_BATCHES + 10) {
            spool_push(
                &mut s,
                OtlpBatch {
                    path: "/v1/logs",
                    json: i.to_string(),
                },
            );
        }
        assert_eq!(s.len(), SPOOL_MAX_BATCHES);
        // Oldest evicted → front is batch #10, not #0.
        assert_eq!(s.front().map(|b| b.json.as_str()), Some("10"));
    }

    // Full push path against a stub hub: flush encodes logs + spans to OTLP/JSON
    // and POSTs both to /v1/logs + /v1/traces with the bearer; a 2xx clears the
    // spool.
    #[tokio::test]
    async fn flush_pushes_otlp_with_bearer_and_clears_spool() {
        use axum::extract::State;
        use axum::{Router, routing::any};
        use std::sync::{Arc, Mutex};

        type Rec = Arc<Mutex<Vec<(String, String, String)>>>; // (path, auth, body)
        let rec: Rec = Arc::new(Mutex::new(Vec::new()));

        async fn capture(State(rec): State<Rec>, req: axum::extract::Request) -> &'static str {
            let path = req.uri().path().to_string();
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            if let Ok(mut g) = rec.lock() {
                g.push((
                    path,
                    auth,
                    String::from_utf8(body.to_vec()).expect("a UTF-8 body"),
                ));
            }
            "OK"
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let app = Router::new().fallback(any(capture)).with_state(rec.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let base = format!("http://127.0.0.1:{port}");
        let token = "x".repeat(MIN_TOKEN_BYTES);
        let target = HubTarget {
            client: exporter_client(&base).expect("TLS backend"),
            base: base.clone(),
            token: token.clone(),
            service: "svc".to_string(),
        };
        let mut logs = vec![(
            1_700_000_000_000u64,
            "error".to_string(),
            "boom".to_string(),
        )];
        let mut spans = vec![(1_700_000_000_000u64, "db.query".to_string(), 5000u64, true)];
        let mut spool: VecDeque<OtlpBatch> = VecDeque::new();

        flush(
            &target,
            &mut logs,
            &mut spans,
            &mut spool,
            &mut OutcomeLog::new(Instant::now()),
        )
        .await;

        // Both signals delivered; spool empty (success); bearer present; OTLP valid.
        let got = rec.lock().map(|g| g.clone()).unwrap_or_default();
        assert_eq!(got.len(), 2, "expected /v1/logs + /v1/traces, got {got:?}");
        assert!(spool.is_empty(), "spool should be cleared on 2xx");
        let paths: Vec<&str> = got.iter().map(|(p, _, _)| p.as_str()).collect();
        assert!(
            paths.contains(&"/v1/logs") && paths.contains(&"/v1/traces"),
            "{paths:?}"
        );
        for (_, auth, body) in &got {
            assert_eq!(auth, &format!("Bearer {token}"));
            let _: serde_json::Value = serde_json::from_str(body).expect("valid OTLP json");
        }
    }

    // Prove the refusal: the exporter client does NOT follow a redirect. A hub
    // that answers a push with a 307 to a *different* (leak) endpoint must NOT
    // cause the bearer token to be re-sent to that endpoint. reqwest's DEFAULT
    // would follow up to 10 hops and retain `Authorization` across a same-host
    // scheme-downgrade — this asserts our `Policy::none()` prevents that. The
    // leak endpoint records zero requests, and the redirect is surfaced as a
    // non-2xx (the batch is re-spooled, not silently dropped).
    #[tokio::test]
    async fn exporter_does_not_follow_redirect_and_never_leaks_bearer() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use axum::{Router, routing::any};
        use std::sync::{Arc, Mutex};

        // The leak target: any request here is a token-leak failure.
        let leak_hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        async fn leak(State(hits): State<Arc<Mutex<Vec<String>>>>, req: axum::extract::Request) {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();
            if let Ok(mut g) = hits.lock() {
                g.push(auth);
            }
        }
        let leak_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind leak");
        let leak_port = leak_listener.local_addr().expect("addr").port();
        let leak_app = Router::new()
            .fallback(any(leak))
            .with_state(leak_hits.clone());
        tokio::spawn(async move {
            let _ = axum::serve(leak_listener, leak_app).await;
        });

        // The hub: answers every push with a 307 redirect to the leak target.
        let leak_base = format!("http://127.0.0.1:{leak_port}");
        async fn redirect(State(loc): State<String>) -> axum::response::Response {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, format!("{loc}/leak"))],
                "moved",
            )
                .into_response()
        }
        let hub_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind hub");
        let hub_port = hub_listener.local_addr().expect("addr").port();
        let hub_app = Router::new()
            .fallback(any(redirect))
            .with_state(leak_base.clone());
        tokio::spawn(async move {
            let _ = axum::serve(hub_listener, hub_app).await;
        });

        let base = format!("http://127.0.0.1:{hub_port}");
        let token = "x".repeat(MIN_TOKEN_BYTES);
        let target = HubTarget {
            client: exporter_client(&base).expect("TLS backend"),
            base: base.clone(),
            token: token.clone(),
            service: "svc".to_string(),
        };
        let batch = OtlpBatch {
            path: "/v1/logs",
            json: "{}".to_string(),
        };

        // A 307 is not a 2xx → push_one reports a refusal (batch is re-spooled).
        let url = format!("{base}{}", batch.path);
        let outcome = push_one(&target, &url, &batch).await;
        assert!(
            matches!(outcome, PushOutcome::Refused(s) if s.as_u16() == 307),
            "a 3xx redirect must NOT count as a successful push"
        );

        // The refusal is surfaced as a log line naming the status, never the bearer.
        let now = Instant::now();
        let line = OutcomeLog::new(now)
            .observe(now, &url, &outcome, &failure_note(batch.path))
            .expect("a refusal is logged");
        assert!(line.contains("HTTP 307"), "{line}");
        assert!(line.contains("re-spooled"), "{line}");
        assert!(!line.contains(&token), "{line}");

        // The load-bearing assertion: the redirect was NOT followed, so the leak
        // endpoint saw no request at all — the bearer never crossed to it.
        let hits = leak_hits.lock().map(|g| g.clone()).unwrap_or_default();
        assert!(
            hits.is_empty(),
            "exporter followed the redirect and leaked to the redirect target: {hits:?}"
        );
    }
    // A failing hub costs one push per flush, not one per spooled batch, and
    // every batch stays spooled in order.
    #[tokio::test]
    async fn first_failure_respools_the_rest_untried() {
        use axum::extract::State;
        use axum::{Router, routing::any};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        async fn refuse(State(hits): State<Arc<AtomicUsize>>) -> axum::http::StatusCode {
            hits.fetch_add(1, Ordering::SeqCst);
            axum::http::StatusCode::UNAUTHORIZED
        }
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let app = Router::new().fallback(any(refuse)).with_state(hits.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base = format!("http://127.0.0.1:{port}");
        let target = HubTarget {
            client: exporter_client(&base).expect("TLS backend"),
            base,
            token: "x".repeat(MIN_TOKEN_BYTES),
            service: "svc".to_string(),
        };
        let mut spool: VecDeque<OtlpBatch> = ["a", "b", "c"]
            .into_iter()
            .map(|j| OtlpBatch {
                path: "/v1/logs",
                json: j.to_string(),
            })
            .collect();
        flush(
            &target,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut spool,
            &mut OutcomeLog::new(Instant::now()),
        )
        .await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let left: Vec<&str> = spool.iter().map(|b| b.json.as_str()).collect();
        assert_eq!(left, ["a", "b", "c"]);
    }
}

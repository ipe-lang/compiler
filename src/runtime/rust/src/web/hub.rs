//! Hub read-side kernels — the bundled console's data plane on Rust.
//!
//! The console (`ipe-bundled/console`) is itself a `Ipe.Web` app; its
//! `HubStore.ipe` declares twelve `Kernel.kernel "Hub_read*"` bindings that the
//! Rust codegen lowers to the `hub_*` functions in this module. Each reads the
//! SQLite telemetry **spill** (`IPE_CONSOLE_HUB_DB` / the `dbPath` arg, written
//! by the dual-write) and returns the console's typed `State*` record shape.
//!
//! ## Why generic over the return type
//!
//! The `State*` records (`StateOverview`, `StateLogEntry`, …) are *project-
//! generated* — the runtime crate cannot name them. So every kernel is generic
//! over `A: DeserializeOwned`: it builds a `serde_json::Value` whose keys match
//! the record's (camelCase, serde-default) field names and `from_value::<A>`s it.
//! The call sites in the generated `hub_store.rs` infer `A` from the concretely-
//! typed `StateStore` fields — no turbofish, no `Any`, no downcast.
//!
//! ## No panic vectors (the Rust backend's reason to exist)
//!
//! A missing/unreadable spill file, a SQL error, or a JSON-decode miss degrades
//! to an **empty result** plus a structured `warn` — never `?`-into-panic, never
//! `unwrap`/`expect`/indexing (a missing hub store yields `Ok([])`). The kernel
//! owns both the SELECT and the `Value` shape, so a producer/consumer schema
//! mismatch cannot arise.

use super::super::core::{IpeResult, IpeTask, ok_res, str_err};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::future::Future;

// ─── Tenant-prefix SQL enforcement ─────────────────────────────────────────
//
// CONSUMER side of tenant scoping: the SQL-layer exact-prefix predicate, the
// `reject_cross_tenant_svc` gate, and the task-local that carries a tenant
// prefix through a request. Both layers judge the same `TenantPrefix` with the
// same relation (`str::starts_with`), so an explicit `service` argument and an
// unscoped read cannot disagree on what is in scope. Every reader that returns,
// names or counts a service's rows applies the predicate: the four `read_*`
// builders, the service list, the per-service stats and the overview counts.
//
// The PRODUCER side — deriving a tenant prefix from a live session's
// authenticated identity (`id.Claims["tenant"]`) and calling
// `with_tenant_prefix` from the request-dispatch loop — depends on
// `IPE_CONSOLE_AUTH=app` (the row-poly `consoleAuth` callback that mints a
// per-session `Identity` with `claims`), which this Rust runtime does not
// implement: `ConsoleAuthMode::App` (`src/runtime/rust/src/telemetry.rs`) is
// refused with 501 by `gate_decision` in `src/runtime/rust/src/web/console.rs`,
// and `hub_current_identity` (below) returns the empty identity for the same
// reason. Until it lands, `with_tenant_prefix` is called by tests only and
// every live request runs unscoped.

/// A tenant's service-name prefix, non-empty by construction.
///
/// "No tenant" is `Option::None`, never an empty prefix, so an empty string
/// cannot stand in for a tenant whose scope would then admit every service.
/// The prefix is compared literally and case-sensitively: no character of it
/// is a wildcard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantPrefix(String);

impl TenantPrefix {
    /// Build a tenant prefix; `None` for the empty string.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Option<Self> {
        let prefix = prefix.into();
        if prefix.is_empty() {
            None
        } else {
            Some(Self(prefix))
        }
    }

    /// The prefix text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `service` lies in this tenant's scope (byte-exact prefix).
    fn admits(&self, service: &str) -> bool {
        service.starts_with(&self.0)
    }
}

tokio::task_local! {
    /// The tenant scope in effect for the current request. Unset outside a
    /// tenant-scoped session, in which case every service is in scope.
    static TENANT_PREFIX: TenantPrefix;
}

/// Run future `f` with `prefix` available to [`current_tenant_prefix`] for
/// `f`'s ENTIRE execution — across every `.await` point, not just its
/// synchronous construction.
///
/// This is the `.scope(value, future).await` async form (mirrors
/// `db.rs`'s `TXN_CONN.scope(..)` pattern), deliberately NOT
/// `LocalKey::sync_scope` (mirrors `pubsub.rs`'s `SESSION_SID` pattern):
/// `sync_scope` only holds the task-local for a SYNCHRONOUS closure, and
/// [`current_tenant_prefix`] is read deep inside a lazily-polled
/// `Box::pin(async move { .. })` future body (`hub_read_filtered_logs` and
/// siblings) — by the time that body runs, a `sync_scope`-based design would
/// have popped the scope, silently reading every request as unscoped. The
/// `.scope(..).await` form keeps the task-local set for as long as the awaited
/// future is being polled, which is the lifetime this gate needs.
pub async fn with_tenant_prefix<R>(prefix: TenantPrefix, f: impl Future<Output = R>) -> R {
    TENANT_PREFIX.scope(prefix, f).await
}

fn current_tenant_prefix() -> Option<TenantPrefix> {
    TENANT_PREFIX.try_with(Clone::clone).ok()
}

/// Enforce that an explicit service-name argument is scoped within the
/// caller's tenant.
///
/// `Ok(effective_svc)` when the call may proceed (no tenant in scope, so every
/// svc is in scope; or `svc == ""` so the tenant prefix alone drives scoping;
/// or the tenant admits `svc`). `Err(())` when `svc` is outside the tenant's
/// scope — the caller MUST refuse with an `Err`, never silently drop the
/// tenant filter and fall through to an unscoped read.
fn reject_cross_tenant_svc(svc: &str, tenant: Option<&TenantPrefix>) -> Result<String, ()> {
    match tenant {
        Some(t) if !svc.is_empty() && !t.admits(svc) => Err(()),
        _ => Ok(svc.to_string()),
    }
}

/// A query over the SQLite telemetry spill.
type SpillQuery<'q> =
    sqlx::query::Query<'q, sqlx::Sqlite, <sqlx::Sqlite as sqlx::Database>::Arguments<'q>>;

/// The tenant-scoping predicate of one spill query.
///
/// Appended to the SQL text once, then bound at the same placeholder
/// position. The shape is the runtime's one exact-prefix rendering
/// ([`crate::db::text_prefix_equals_sql`]), which is exactly
/// [`TenantPrefix::admits`]: SQLite's `substr`/`length` count characters on
/// TEXT and `=` compares with the binary collation, so the prefix carries no
/// wildcard and no case folding (unlike `LIKE`).
struct TenantFilter<'p>(&'p TenantPrefix);

impl<'p> TenantFilter<'p> {
    /// Append the predicate to `sql` when a tenant is in scope.
    fn push(sql: &mut String, tenant: Option<&'p TenantPrefix>) -> Option<Self> {
        let tenant = tenant?;
        sql.push_str(" AND ");
        sql.push_str(crate::db::text_prefix_equals_sql("service_name").as_str());
        Some(Self(tenant))
    }

    /// Bind the prefix to the predicate's two placeholders.
    fn bind<'q>(self, q: SpillQuery<'q>) -> SpillQuery<'q>
    where
        'p: 'q,
    {
        q.bind(self.0.as_str()).bind(self.0.as_str())
    }
}

/// Default per-table read cap (200 for logs/metrics).
const LOG_LIMIT: i64 = 200;

/// The console's `LogFilter` shape (serde-mirrors `StateLogFilter`). Kernels
/// take the filter generic `F: Serialize`, re-serialize it, and decode into
/// this — so the runtime never names the project-generated `StateLogFilter`.
#[derive(Deserialize, Default)]
#[allow(non_snake_case)]
struct HubLogFilter {
    #[serde(default)]
    query: String,
    #[serde(default)]
    session: String,
    #[serde(default)]
    showDebug: bool,
    #[serde(default)]
    showInfo: bool,
    #[serde(default)]
    showWarn: bool,
    #[serde(default)]
    showError: bool,
}

/// Re-serialize any `F: Serialize` filter into `HubLogFilter`; a shape mismatch
/// degrades to the default (no filtering) — never a panic.
fn decode_filter<F: Serialize>(filter: F) -> HubLogFilter {
    serde_json::to_value(filter)
        .ok()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

/// The store applies an `=` level filter, so only "exactly one level toggled"
/// is expressible; zero or 2+ → no filter.
fn pick_single_level(f: &HubLogFilter) -> Option<&'static str> {
    let mut chosen = None;
    let mut count = 0;
    for (on, name) in [
        (f.showDebug, "debug"),
        (f.showInfo, "info"),
        (f.showWarn, "warn"),
        (f.showError, "error"),
    ] {
        if on {
            count += 1;
            chosen = Some(name);
        }
    }
    if count == 1 { chosen } else { None }
}

/// Cap on the `attrs` JSON byte length parsed per row. A telemetry writer
/// controls this cell (a SQLite cell is bounded only by the ~1 GB row limit);
/// parsing an oversized blob across up to `STATS_ROW_CAP` rows would amplify
/// into a memory-exhaustion vector, so anything beyond the cap degrades to an
/// empty map — the same total fallback as a parse failure.
const ATTRS_MAX_BYTES: usize = 64 * 1024;

/// Parse the `attrs` JSON column into a string→string map; an oversized blob,
/// non-object value, or parse failure → empty map (graceful, total).
fn parse_attrs(raw: &str) -> HashMap<String, String> {
    if raw.len() > ATTRS_MAX_BYTES {
        return HashMap::new();
    }
    serde_json::from_str(raw).unwrap_or_default()
}

/// Build the `LogEntry`-shaped JSON array applying query/session filters.
///
/// `service` empty → no service scoping. `tenant` `None` → no tenant scoping
/// (every service in scope); `Some` → additionally requires the service name
/// to start with the prefix (see [`TenantFilter`]). Returns an empty array on
/// any open/SQL failure.
async fn read_logs_value(
    db_path: &str,
    service: &str,
    tenant: Option<&TenantPrefix>,
    filter: HubLogFilter,
) -> Value {
    let Some(pool) = open_spill(db_path).await else {
        return Value::Array(vec![]);
    };
    let mut sql = String::from(
        "SELECT service_name, time, level, message, trace_id, span_id, attrs \
         FROM telemetry_log WHERE 1=1",
    );
    let level = pick_single_level(&filter);
    if !service.is_empty() {
        sql.push_str(" AND service_name = ?");
    }
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    if level.is_some() {
        sql.push_str(" AND level = ?");
    }
    sql.push_str(" ORDER BY time DESC, id DESC LIMIT ?");

    let mut q = sqlx::query(&sql);
    if !service.is_empty() {
        q = q.bind(service);
    }
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    if let Some(lv) = level {
        q = q.bind(lv);
    }
    q = q.bind(LOG_LIMIT);

    let rows = match q.fetch_all(&pool).await {
        Ok(r) => r,
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("readLogs: {e}"));
            return Value::Array(vec![]);
        }
    };

    let ql = filter.query.to_lowercase();
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let service_name: String = r.try_get("service_name").unwrap_or_default();
        let message: String = r.try_get("message").unwrap_or_default();
        let attrs = parse_attrs(&r.try_get::<String, _>("attrs").unwrap_or_default());

        // Client-side free-text filter: lower-substring of message | service.
        if !ql.is_empty()
            && !message.to_lowercase().contains(&ql)
            && !service_name.to_lowercase().contains(&ql)
        {
            continue;
        }
        // Client-side session filter.
        if !filter.session.is_empty()
            && attrs.get("session_id").map(String::as_str) != Some(filter.session.as_str())
        {
            continue;
        }
        let attr = |k: &str| attrs.get(k).cloned().unwrap_or_default();
        // Derive status/latency from the log's attrs —
        // the writer carries `status` / `latency_ms` keys (the same `latency_ms`
        // `aggregate_service_stat` reads). Missing/unparseable → 0.0.
        let status = attrs
            .get("status")
            .and_then(|s| parse_float_attr(s))
            .unwrap_or(0.0);
        let latency_ms = attrs
            .get("latency_ms")
            .and_then(|s| parse_float_attr(s))
            .unwrap_or(0.0);
        out.push(json!({
            "time": r.try_get::<String, _>("time").unwrap_or_default(),
            "level": r.try_get::<String, _>("level").unwrap_or_default(),
            "message": message,
            "subapp": service_name,
            "reqId": attr("req_id"),
            "sessionId": attr("session_id"),
            "userLabel": attr("user_label"),
            "route": attr("route"),
            "status": status,
            "latencyMs": latency_ms,
        }));
    }
    Value::Array(out)
}

/// `Hub_readLogs : String -> LogFilter -> Task Error (List LogEntry)`. Reads
/// the caller's current tenant scope directly (no explicit `service` to
/// validate) — a tenant-scoped session cannot bypass the gate by calling the
/// no-service variant instead of `Hub_readFilteredLogs`.
pub fn hub_read_logs<E, A, F>(db_path: String, filter: F) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
    F: Serialize + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let f = decode_filter(filter);
        let arr = read_logs_value(&db_path, "", tenant.as_ref(), f).await;
        decode_rows(arr)
    })
}

/// `Hub_readFilteredLogs : String -> String -> LogFilter -> Task Error (List LogEntry)`.
/// Enforces the tenant-prefix gate on the explicit `service` argument
/// BEFORE building any SQL — a cross-tenant `service` is rejected with `Err`,
/// never silently dropped.
pub fn hub_read_filtered_logs<E, A, F>(db_path: String, service: String, filter: F) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
    F: Serialize + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let effective_svc = match reject_cross_tenant_svc(&service, tenant.as_ref()) {
            Ok(s) => s,
            Err(()) => {
                return IpeResult::Err(str_err(
                    "hub.readFilteredLogs: service outside tenant scope",
                ));
            }
        };
        let f = decode_filter(filter);
        let arr = read_logs_value(&db_path, &effective_svc, tenant.as_ref(), f).await;
        decode_rows(arr)
    })
}

/// Deserialize a built `Value` into the project-generated record type `A`. A
/// decode miss degrades to the type's `serde` default via an empty array /
/// object — but since the kernel OWNS the Value shape it always matches, so the
/// `Err` arm is unreachable in practice; it still returns `Ok` of the
/// empty-array decode rather than surfacing an error (total, no panic).
fn decode_rows<E, A>(arr: Value) -> IpeResult<E, A>
where
    E: From<String>,
    A: DeserializeOwned,
{
    match serde_json::from_value::<A>(arr) {
        Ok(a) => ok_res(a),
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("decode_rows: {e}"));
            // Fall back to decoding an empty array (List records) — if A is not
            // a list this also fails, in which case surface a structured Err
            // (the value system models it; never a panic).
            match serde_json::from_value::<A>(Value::Array(vec![])) {
                Ok(a) => ok_res(a),
                Err(_) => IpeResult::Err(str_err(&format!("hub.decode: {e}"))),
            }
        }
    }
}

const METRIC_LIMIT: i64 = 200;
const TRACE_LIMIT: i64 = 100;
const ERROR_LIMIT: i64 = 500;

/// Build the `MetricRow`-shaped JSON array.
///
/// `labels` is the attrs map rendered `k=v, k=v` (keys sorted for stable
/// output); `sum`/`count` are 0 (the spill doesn't carry histogram aggregates
/// yet). `tenant` `None` → no tenant scoping; see [`TenantFilter`].
async fn read_metrics_value(db_path: &str, service: &str, tenant: Option<&TenantPrefix>) -> Value {
    let Some(pool) = open_spill(db_path).await else {
        return Value::Array(vec![]);
    };
    let mut sql = String::from("SELECT name, type, value, attrs FROM telemetry_metric WHERE 1=1");
    if !service.is_empty() {
        sql.push_str(" AND service_name = ?");
    }
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    sql.push_str(" ORDER BY time DESC, id DESC LIMIT ?");
    let mut q = sqlx::query(&sql);
    if !service.is_empty() {
        q = q.bind(service);
    }
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    let rows = match q.bind(METRIC_LIMIT).fetch_all(&pool).await {
        Ok(r) => r,
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("readMetrics: {e}"));
            return Value::Array(vec![]);
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let attrs = parse_attrs(&r.try_get::<String, _>("attrs").unwrap_or_default());
        let mut keys: Vec<&String> = attrs.keys().collect();
        keys.sort();
        let labels = keys
            .iter()
            .map(|k| format!("{k}={}", attrs.get(*k).map(String::as_str).unwrap_or("")))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(json!({
            "name": r.try_get::<String, _>("name").unwrap_or_default(),
            "typ": r.try_get::<String, _>("type").unwrap_or_default(),
            "labels": labels,
            "value": r.try_get::<f64, _>("value").unwrap_or(0.0),
            "sum": 0.0,
            "count": 0.0,
        }));
    }
    Value::Array(out)
}

/// Milliseconds between two RFC3339 timestamps; 0 when either is empty or
/// unparseable (total — never panics). Implements zero-guarded `Sub`.
fn duration_ms(start: &str, end: &str) -> f64 {
    if start.is_empty() || end.is_empty() {
        return 0.0;
    }
    match (
        chrono::DateTime::parse_from_rfc3339(start),
        chrono::DateTime::parse_from_rfc3339(end),
    ) {
        (Ok(s), Ok(e)) => (e - s).num_milliseconds() as f64,
        _ => 0.0,
    }
}

/// Build the `TraceRow`-shaped JSON array.
///
/// `kind`=service, `durationMs` from start/end, `status` from attrs. `tenant`
/// `None` → no tenant scoping; see [`TenantFilter`].
async fn read_traces_value(db_path: &str, service: &str, tenant: Option<&TenantPrefix>) -> Value {
    let Some(pool) = open_spill(db_path).await else {
        return Value::Array(vec![]);
    };
    let mut sql = String::from(
        "SELECT service_name, name, trace_id, span_id, parent_id, start_time, end_time, attrs \
         FROM telemetry_span WHERE 1=1",
    );
    if !service.is_empty() {
        sql.push_str(" AND service_name = ?");
    }
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    sql.push_str(" ORDER BY time DESC, id DESC LIMIT ?");
    let mut q = sqlx::query(&sql);
    if !service.is_empty() {
        q = q.bind(service);
    }
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    let rows = match q.bind(TRACE_LIMIT).fetch_all(&pool).await {
        Ok(r) => r,
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("readTraces: {e}"));
            return Value::Array(vec![]);
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let start: String = r.try_get("start_time").unwrap_or_default();
        let end: String = r.try_get("end_time").unwrap_or_default();
        let attrs = parse_attrs(&r.try_get::<String, _>("attrs").unwrap_or_default());
        out.push(json!({
            "traceId": r.try_get::<String, _>("trace_id").unwrap_or_default(),
            "spanId": r.try_get::<String, _>("span_id").unwrap_or_default(),
            "parentId": r.try_get::<String, _>("parent_id").unwrap_or_default(),
            "name": r.try_get::<String, _>("name").unwrap_or_default(),
            "kind": r.try_get::<String, _>("service_name").unwrap_or_default(),
            "startTime": start.clone(),
            "durationMs": duration_ms(&start, &end),
            "status": attrs.get("status").cloned().unwrap_or_default(),
        }));
    }
    Value::Array(out)
}

/// Build the `ErrorRow`-shaped JSON array of error-level logs.
///
/// Grouped by message → `{count, message}`, descending by count for a stable,
/// useful order. `tenant` `None` → no tenant scoping; see [`TenantFilter`].
async fn read_errors_value(db_path: &str, service: &str, tenant: Option<&TenantPrefix>) -> Value {
    let Some(pool) = open_spill(db_path).await else {
        return Value::Array(vec![]);
    };
    let mut sql = String::from("SELECT message FROM telemetry_log WHERE level = 'error'");
    if !service.is_empty() {
        sql.push_str(" AND service_name = ?");
    }
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    sql.push_str(" ORDER BY time DESC, id DESC LIMIT ?");
    let mut q = sqlx::query(&sql);
    if !service.is_empty() {
        q = q.bind(service);
    }
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    let rows = match q.bind(ERROR_LIMIT).fetch_all(&pool).await {
        Ok(r) => r,
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("readErrors: {e}"));
            return Value::Array(vec![]);
        }
    };
    let mut counts: HashMap<String, i64> = HashMap::new();
    for r in &rows {
        let msg: String = r.try_get("message").unwrap_or_default();
        *counts.entry(msg).or_insert(0) += 1;
    }
    let mut pairs: Vec<(String, i64)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let out = pairs
        .into_iter()
        .map(|(message, count)| json!({ "count": count, "message": message }))
        .collect();
    Value::Array(out)
}

/// `Hub_readMetrics : String -> Task Error (List MetricRow)`. Reads the
/// caller's current tenant scope directly — see [`hub_read_logs`]'s doc.
pub fn hub_read_metrics<E, A>(db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        decode_rows(read_metrics_value(&db_path, "", tenant.as_ref()).await)
    })
}

/// `Hub_readFilteredMetrics : String -> String -> Task Error (List MetricRow)`.
/// Enforces the tenant-prefix gate on `service` before building any SQL — see
/// [`hub_read_filtered_logs`]'s doc.
pub fn hub_read_filtered_metrics<E, A>(db_path: String, service: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let effective_svc = match reject_cross_tenant_svc(&service, tenant.as_ref()) {
            Ok(s) => s,
            Err(()) => {
                return IpeResult::Err(str_err(
                    "hub.readFilteredMetrics: service outside tenant scope",
                ));
            }
        };
        decode_rows(read_metrics_value(&db_path, &effective_svc, tenant.as_ref()).await)
    })
}

/// `Hub_readTraces : String -> Task Error (List TraceRow)`. Reads the
/// caller's current tenant scope directly — see [`hub_read_logs`]'s doc.
pub fn hub_read_traces<E, A>(db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        decode_rows(read_traces_value(&db_path, "", tenant.as_ref()).await)
    })
}

/// `Hub_readFilteredTraces : String -> String -> Task Error (List TraceRow)`.
/// Enforces the tenant-prefix gate on `service` before building any SQL — see
/// [`hub_read_filtered_logs`]'s doc.
pub fn hub_read_filtered_traces<E, A>(db_path: String, service: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let effective_svc = match reject_cross_tenant_svc(&service, tenant.as_ref()) {
            Ok(s) => s,
            Err(()) => {
                return IpeResult::Err(str_err(
                    "hub.readFilteredTraces: service outside tenant scope",
                ));
            }
        };
        decode_rows(read_traces_value(&db_path, &effective_svc, tenant.as_ref()).await)
    })
}

/// `Hub_readErrors : String -> Task Error (List ErrorRow)`. Reads the
/// caller's current tenant scope directly — see [`hub_read_logs`]'s doc.
pub fn hub_read_errors<E, A>(db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        decode_rows(read_errors_value(&db_path, "", tenant.as_ref()).await)
    })
}

/// `Hub_readFilteredErrors : String -> String -> Task Error (List ErrorRow)`.
/// Enforces the tenant-prefix gate on `service` before building any SQL — see
/// [`hub_read_filtered_logs`]'s doc.
pub fn hub_read_filtered_errors<E, A>(db_path: String, service: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let effective_svc = match reject_cross_tenant_svc(&service, tenant.as_ref()) {
            Ok(s) => s,
            Err(()) => {
                return IpeResult::Err(str_err(
                    "hub.readFilteredErrors: service outside tenant scope",
                ));
            }
        };
        decode_rows(read_errors_value(&db_path, &effective_svc, tenant.as_ref()).await)
    })
}

// ── Overview, ServiceStats, Identity ────────────────────────────────────────

/// The fixed set of telemetry tables [`count_table`] may count. Modelling the
/// table as a closed enum (not a `&str`) makes a runtime-derived table name
/// unrepresentable, so the `format!`-built SQL can only ever interpolate a
/// hardcoded literal — SQL injection here is impossible by construction, not
/// by caller discipline.
#[derive(Clone, Copy)]
enum TelemetryTable {
    Log,
    Metric,
    Span,
}

impl TelemetryTable {
    /// The hardcoded table name. Never derived from runtime input.
    const fn name(self) -> &'static str {
        match self {
            TelemetryTable::Log => "telemetry_log",
            TelemetryTable::Metric => "telemetry_metric",
            TelemetryTable::Span => "telemetry_span",
        }
    }
}

/// `count(*)` for one telemetry table within `tenant`'s scope; 0 on any
/// failure (total).
async fn count_table(
    pool: &SqlitePool,
    table: TelemetryTable,
    tenant: Option<&TenantPrefix>,
) -> i64 {
    // `table.name()` is a compile-time constant from a closed enum; the
    // interpolation cannot carry attacker input.
    let mut sql = format!("SELECT COUNT(*) AS n FROM {} WHERE 1=1", table.name());
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    let mut q = sqlx::query(&sql);
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    match q.fetch_one(pool).await {
        Ok(row) => row.try_get::<i64, _>("n").unwrap_or(0),
        Err(_) => 0,
    }
}

/// `Hub_readOverview : String -> Task Error Overview`: a default Overview
/// with the live row counts spliced in.
pub fn hub_read_overview<E, A>(db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let tenant = current_tenant_prefix();
        let tenant = tenant.as_ref();
        let (logs, metrics, spans) = match open_spill(&db_path).await {
            Some(pool) => (
                count_table(&pool, TelemetryTable::Log, tenant).await,
                count_table(&pool, TelemetryTable::Metric, tenant).await,
                count_table(&pool, TelemetryTable::Span, tenant).await,
            ),
            None => (0, 0, 0),
        };
        let ov = json!({
            "ipeVersion": "hub",
            "commit": "",
            "builtAt": "",
            "uptimeSeconds": 0,
            "requestsTotal": logs + metrics + spans,
            "errorRate5xx": 0.0,
            "bufferLogUsed": logs,
            "bufferTraceUsed": spans,
            "productionMode": false,
        });
        decode_one(ov)
    })
}

/// `Hub_currentIdentity : String -> Task Error Identity`. The spill-only console
/// has no session identity (that's A-territory / live-session plumbing), so
/// return the empty identity — a graceful default, never an error.
pub fn hub_current_identity<E, A>(_db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move { decode_one(json!({ "subject": "", "email": "", "claims": {} })) })
}

// — ServiceStats aggregation —

const STATS_WINDOW_SECS: i64 = 60;
const STATS_BUCKET_COUNT: usize = 30;
const STATS_ROW_CAP: i64 = 10_000;

/// Nearest-rank p-th percentile; 0 for empty input (= "no observations", not
/// "zero latency").
fn percentile(vals: &[f64], p: f64) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    let mut sorted = vals.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mut idx = (p * sorted.len() as f64).ceil() as isize - 1;
    if idx < 0 {
        idx = 0;
    }
    let idx = (idx as usize).min(sorted.len() - 1);
    sorted.get(idx).copied().unwrap_or(0.0)
}

/// 3-state pill from the recent error rate (>5% err, ≥1% warn, else ok).
fn classify_status(error_rate: f64) -> &'static str {
    if error_rate > 0.05 {
        "err"
    } else if error_rate >= 0.01 {
        "warn"
    } else {
        "ok"
    }
}

/// Parse an attr value string ("3.14"/"42") to f64; `None` (skip the
/// observation) on empty/unparseable.
fn parse_float_attr(raw: &str) -> Option<f64> {
    if raw.is_empty() {
        None
    } else {
        raw.trim().parse::<f64>().ok()
    }
}

/// Bucket index for `ts` within `[since, since + count*bucket]`; `None` outside.
fn bucket_index(ts_ms: i64, since_ms: i64, bucket_ms: i64) -> Option<usize> {
    if bucket_ms <= 0 {
        return None;
    }
    let off = ts_ms - since_ms;
    if off < 0 {
        return None;
    }
    Some((off / bucket_ms) as usize)
}

fn parse_ms(rfc: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(rfc)
        .ok()
        .map(|d| d.timestamp_millis())
}

/// Aggregate one service's last-60 s telemetry into the ServiceStat JSON shape.
/// Window-filters via RFC3339 parse (robust against writer/reader time-format
/// drift); all slice access is checked.
async fn aggregate_service_stat(pool: &SqlitePool, svc: &str) -> Value {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let since_ms = now_ms - STATS_WINDOW_SECS * 1000;
    let window_sec = STATS_WINDOW_SECS as f64;
    let bucket_ms = (STATS_WINDOW_SECS * 1000) / STATS_BUCKET_COUNT as i64;

    // Recent logs for the service.
    let log_rows = sqlx::query(
        "SELECT time, level, attrs FROM telemetry_log WHERE service_name = ? \
         ORDER BY time DESC LIMIT ?",
    )
    .bind(svc)
    .bind(STATS_ROW_CAP)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let span_rows = sqlx::query(
        "SELECT start_time, end_time FROM telemetry_span WHERE service_name = ? \
         ORDER BY time DESC LIMIT ?",
    )
    .bind(svc)
    .bind(STATS_ROW_CAP)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut log_count = 0usize;
    let mut error_count = 0usize;
    let mut latencies: Vec<f64> = Vec::new();
    let mut req_counts = vec![0i64; STATS_BUCKET_COUNT];
    let mut lat_buckets: Vec<Vec<f64>> = vec![Vec::new(); STATS_BUCKET_COUNT];

    for r in &log_rows {
        let t: String = r.try_get("time").unwrap_or_default();
        let Some(ts) = parse_ms(&t) else { continue };
        if ts < since_ms || ts > now_ms {
            continue;
        }
        log_count += 1;
        let level: String = r.try_get("level").unwrap_or_default();
        if level == "error" {
            error_count += 1;
        }
        let attrs = parse_attrs(&r.try_get::<String, _>("attrs").unwrap_or_default());
        let lat = attrs.get("latency_ms").and_then(|s| parse_float_attr(s));
        if let Some(v) = lat {
            latencies.push(v);
        }
        if let Some(idx) = bucket_index(ts, since_ms, bucket_ms) {
            if let Some(c) = req_counts.get_mut(idx) {
                *c += 1;
            }
            if let Some(v) = lat
                && let Some(b) = lat_buckets.get_mut(idx)
            {
                b.push(v);
            }
        }
    }

    for r in &span_rows {
        let start: String = r.try_get("start_time").unwrap_or_default();
        let end: String = r.try_get("end_time").unwrap_or_default();
        let (Some(s_ms), Some(e_ms)) = (parse_ms(&start), parse_ms(&end)) else {
            continue;
        };
        let ms = (e_ms - s_ms) as f64;
        if ms <= 0.0 {
            continue;
        }
        latencies.push(ms);
        if let Some(idx) = bucket_index(s_ms, since_ms, bucket_ms)
            && let Some(b) = lat_buckets.get_mut(idx)
        {
            b.push(ms);
        }
    }

    let reqs_per_sec = log_count as f64 / window_sec;
    let error_rate = if log_count > 0 {
        error_count as f64 / log_count as f64
    } else {
        0.0
    };
    let bucket_sec = (bucket_ms as f64 / 1000.0).max(1.0);
    let spark_rps: Vec<f64> = req_counts.iter().map(|c| *c as f64 / bucket_sec).collect();
    let spark_p95: Vec<f64> = lat_buckets.iter().map(|b| percentile(b, 0.95)).collect();

    json!({
        "name": svc,
        "status": classify_status(error_rate),
        "reqsPerSec": reqs_per_sec,
        "p95Ms": percentile(&latencies, 0.95),
        "errorRate": error_rate,
        "sparkRps": spark_rps,
        "sparkP95": spark_p95,
    })
}

/// `Hub_readServiceStats : String -> Task Error (List ServiceStat)`.
pub fn hub_read_service_stats<E, A>(db_path: String) -> IpeTask<E, A>
where
    E: Send + From<String> + 'static,
    A: DeserializeOwned + Send + 'static,
{
    Box::pin(async move {
        let Some(pool) = open_spill(&db_path).await else {
            return decode_rows(Value::Array(vec![]));
        };
        let tenant = current_tenant_prefix();
        let services = match distinct_services(&pool, tenant.as_ref()).await {
            Ok(services) => services,
            Err(e) => {
                crate::system::emit_runtime_log("hub", &format!("serviceStats services: {e}"));
                return decode_rows(Value::Array(vec![]));
            }
        };
        let mut out = Vec::with_capacity(services.len());
        for svc in &services {
            out.push(aggregate_service_stat(&pool, svc).await);
        }
        decode_rows(Value::Array(out))
    })
}

/// Deserialize a single built object `Value` into the project record `A`. A
/// decode miss surfaces a typed `Err` (the value system models it; no panic).
fn decode_one<E, A>(obj: Value) -> IpeResult<E, A>
where
    E: From<String>,
    A: DeserializeOwned,
{
    match serde_json::from_value::<A>(obj) {
        Ok(a) => ok_res(a),
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("decode_one: {e}"));
            IpeResult::Err(str_err(&format!("hub.decode: {e}")))
        }
    }
}

/// Open the telemetry spill read-only. `None` (never an error) when the path is
/// empty or the file can't be opened — callers map that to an empty result so a
/// fresh/absent DB renders as "no telemetry yet" — a graceful empty result.
async fn open_spill(db_path: &str) -> Option<SqlitePool> {
    if db_path.is_empty() {
        return None;
    }
    // NOT read-only: the spill is WAL-mode (the parent writer needs concurrent
    // read+write — see telemetry_spill.rs). A read-only connection can't attach
    // the -wal/-shm and so never sees frames the writer committed but hasn't
    // checkpointed; a read-write reader participates in WAL and sees them. The
    // console only ever SELECTs, so rw grants no real write. A missing file fails
    // to connect → None → empty result (no panic, no surfaced error).
    //
    // Use SqliteConnectOptions::from_path (not a format!-built URL) so that
    // special characters in db_path (spaces, '?', '#', etc.) can't corrupt the
    // connection string.
    let opts = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(false)
        // Wait on a WAL writer's lock instead of returning SQLITE_BUSY at once
        // (a spurious empty result), bounded so a wedged writer cannot block the
        // task indefinitely.
        .busy_timeout(crate::system::SQLITE_BUSY_TIMEOUT);
    match SqlitePool::connect_with(opts).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            crate::system::emit_runtime_log("hub", &format!("open_spill {db_path}: {e}"));
            None
        }
    }
}

/// The distinct non-empty `service_name`s across all three telemetry tables
/// within `tenant`'s scope, sorted.
///
/// `LIMIT 200` bounds result allocation and the per-request aggregation
/// fan-out of [`hub_read_service_stats`]: `service_name` is writer-controlled,
/// so an unbounded `UNION` is a memory-amplification vector. The tenant filter
/// runs before the limit, so another tenant's services cannot crowd this
/// tenant's out of the page.
async fn distinct_services(
    pool: &SqlitePool,
    tenant: Option<&TenantPrefix>,
) -> Result<Vec<String>, sqlx::Error> {
    let mut sql = String::from(
        "SELECT service_name FROM (SELECT service_name FROM telemetry_log \
         UNION SELECT service_name FROM telemetry_metric \
         UNION SELECT service_name FROM telemetry_span) WHERE 1=1",
    );
    let tenant_filter = TenantFilter::push(&mut sql, tenant);
    sql.push_str(" ORDER BY service_name LIMIT 200");
    let mut q = sqlx::query(&sql);
    if let Some(tf) = tenant_filter {
        q = tf.bind(q);
    }
    let rows = q.fetch_all(pool).await?;
    Ok(rows
        .iter()
        .filter_map(|r| r.try_get::<String, _>("service_name").ok())
        .filter(|s| !s.is_empty())
        .collect())
}

/// `Hub_listServices : String -> Task Error (List String)` — distinct
/// service_name across all three telemetry tables, sorted.
pub fn hub_list_services<E: Send + From<String> + 'static>(
    db_path: String,
) -> IpeTask<E, Vec<String>> {
    Box::pin(async move {
        let Some(pool) = open_spill(&db_path).await else {
            return ok_res(Vec::new());
        };
        let tenant = current_tenant_prefix();
        match distinct_services(&pool, tenant.as_ref()).await {
            Ok(services) => ok_res(services),
            Err(e) => {
                crate::system::emit_runtime_log("hub", &format!("listServices: {e}"));
                ok_res(Vec::new())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed(path: &str) -> SqlitePool {
        let pool = SqlitePool::connect(&format!("sqlite:{path}?mode=rwc"))
            .await
            .expect("create temp spill");
        sqlx::query(
            "CREATE TABLE telemetry_log (id INTEGER PRIMARY KEY, service_name TEXT, \
             time TEXT, level TEXT, message TEXT, trace_id TEXT, span_id TEXT, attrs TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE telemetry_metric (id INTEGER PRIMARY KEY, service_name TEXT, \
             time TEXT, name TEXT, type TEXT, value REAL, attrs TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE telemetry_span (id INTEGER PRIMARY KEY, service_name TEXT, \
             time TEXT, name TEXT, trace_id TEXT, span_id TEXT, parent_id TEXT, \
             start_time TEXT, end_time TEXT, attrs TEXT)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn list_services_distinct_sorted() {
        let dir = crate::scratch_core::test_temp_root()
            .join(format!("hub-svc-{}.db", std::process::id()));
        let path = dir.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for (tbl, svc) in [
            ("telemetry_log", "b"),
            ("telemetry_log", "a"),
            ("telemetry_span", "a"),
        ] {
            sqlx::query(&format!(
                "INSERT INTO {tbl} (service_name, time) VALUES (?, '2026-01-01T00:00:00Z')"
            ))
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<String>> = hub_list_services(path.clone()).await;
        match res {
            IpeResult::Ok(v) => assert_eq!(v, vec!["a".to_string(), "b".to_string()]),
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn missing_db_is_empty_not_error() {
        let res: IpeResult<String, Vec<String>> =
            hub_list_services("/nonexistent/path/to.db".to_string()).await;
        match res {
            IpeResult::Ok(v) => assert!(v.is_empty()),
            IpeResult::Err(_) => panic!("missing DB must degrade to empty, not error"),
        }
    }

    #[tokio::test]
    async fn empty_path_is_empty() {
        let res: IpeResult<String, Vec<String>> = hub_list_services(String::new()).await;
        assert!(matches!(res, IpeResult::Ok(v) if v.is_empty()));
    }

    #[derive(serde::Serialize)]
    #[allow(non_snake_case)]
    struct TestFilter {
        query: String,
        session: String,
        showDebug: bool,
        showInfo: bool,
        showWarn: bool,
        showError: bool,
    }
    impl TestFilter {
        fn none() -> Self {
            Self {
                query: String::new(),
                session: String::new(),
                showDebug: false,
                showInfo: false,
                showWarn: false,
                showError: false,
            }
        }
    }

    #[tokio::test]
    async fn read_logs_maps_attrs_and_filters_level() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-logs-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for (lvl, msg, attrs) in [
            (
                "info",
                "hello",
                r#"{"req_id":"r1","session_id":"s1","route":"/a"}"#,
            ),
            ("error", "boom", r#"{"req_id":"r2","route":"/b"}"#),
        ] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES ('svc', '2026-01-01T00:00:00Z', ?, ?, ?)",
            )
            .bind(lvl)
            .bind(msg)
            .bind(attrs)
            .execute(&pool)
            .await
            .unwrap();
        }
        // showError only → exactly-one-level → just the error row.
        let f = TestFilter {
            showError: true,
            ..TestFilter::none()
        };
        let res: IpeResult<String, Vec<Value>> = hub_read_logs(path.clone(), f).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["message"], "boom");
                assert_eq!(rows[0]["reqId"], "r2");
                assert_eq!(rows[0]["route"], "/b");
                assert_eq!(rows[0]["subapp"], "svc");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        // Free-text query "hello" → only the info row (no level filter).
        let f2 = TestFilter {
            query: "hello".to_string(),
            ..TestFilter::none()
        };
        let res2: IpeResult<String, Vec<Value>> = hub_read_logs(path.clone(), f2).await;
        match res2 {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["sessionId"], "s1");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn filtered_logs_scopes_to_service() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-flogs-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for svc in ["alpha", "beta"] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'info', 'm', '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<Value>> =
            hub_read_filtered_logs(path.clone(), "alpha".to_string(), TestFilter::none()).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["subapp"], "alpha");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duration_ms_total_and_guarded() {
        assert_eq!(duration_ms("", "2026-01-01T00:00:01Z"), 0.0);
        assert_eq!(duration_ms("nonsense", "alsobad"), 0.0);
        assert_eq!(
            duration_ms("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.250Z"),
            250.0
        );
    }

    #[tokio::test]
    async fn read_metrics_joins_sorted_labels() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-met-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        sqlx::query(
            "INSERT INTO telemetry_metric (service_name, time, name, type, value, attrs) \
             VALUES ('svc', '2026-01-01T00:00:00Z', 'reqs', 'counter', 5.0, ?)",
        )
        .bind(r#"{"zone":"eu","app":"web"}"#)
        .execute(&pool)
        .await
        .unwrap();
        let res: IpeResult<String, Vec<Value>> = hub_read_metrics(path.clone()).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["name"], "reqs");
                assert_eq!(rows[0]["typ"], "counter");
                assert_eq!(rows[0]["value"], 5.0);
                assert_eq!(rows[0]["labels"], "app=web, zone=eu"); // sorted keys
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn read_traces_computes_duration() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-tr-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        sqlx::query(
            "INSERT INTO telemetry_span (service_name, time, name, trace_id, span_id, \
             parent_id, start_time, end_time, attrs) VALUES \
             ('svc', '2026-01-01T00:00:00Z', 'GET /', 't1', 's1', '', \
              '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.100Z', ?)",
        )
        .bind(r#"{"status":"ok"}"#)
        .execute(&pool)
        .await
        .unwrap();
        let res: IpeResult<String, Vec<Value>> = hub_read_traces(path.clone()).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["traceId"], "t1");
                assert_eq!(rows[0]["kind"], "svc");
                assert_eq!(rows[0]["durationMs"], 100.0);
                assert_eq!(rows[0]["status"], "ok");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn read_errors_groups_by_message() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-err-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for msg in ["boom", "boom", "split"] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES ('svc', '2026-01-01T00:00:00Z', 'error', ?, '{}')",
            )
            .bind(msg)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<Value>> = hub_read_errors(path.clone()).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 2);
                // descending by count → "boom" (2) first.
                assert_eq!(rows[0]["message"], "boom");
                assert_eq!(rows[0]["count"], 2);
                assert_eq!(rows[1]["message"], "split");
                assert_eq!(rows[1]["count"], 1);
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn percentile_nearest_rank() {
        assert_eq!(percentile(&[], 0.95), 0.0);
        assert_eq!(percentile(&[5.0], 0.95), 5.0);
        // 100 values 1..=100, p95 nearest-rank = ceil(0.95*100)=95th → 95.
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(percentile(&v, 0.95), 95.0);
    }

    #[test]
    fn classify_status_thresholds() {
        assert_eq!(classify_status(0.0), "ok");
        assert_eq!(classify_status(0.009), "ok");
        assert_eq!(classify_status(0.01), "warn");
        assert_eq!(classify_status(0.05), "warn");
        assert_eq!(classify_status(0.051), "err");
    }

    #[test]
    fn bucket_index_bounds() {
        assert_eq!(bucket_index(0, 0, 0), None); // zero bucket
        assert_eq!(bucket_index(-5, 0, 1000), None); // before window
        assert_eq!(bucket_index(0, 0, 2000), Some(0));
        assert_eq!(bucket_index(2500, 0, 2000), Some(1));
    }

    #[tokio::test]
    async fn overview_splices_counts() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-ov-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        sqlx::query("INSERT INTO telemetry_log (service_name, time) VALUES ('s','t')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO telemetry_span (service_name, time) VALUES ('s','t')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO telemetry_span (service_name, time) VALUES ('s','t')")
            .execute(&pool)
            .await
            .unwrap();
        let res: IpeResult<String, Value> = hub_read_overview(path.clone()).await;
        match res {
            IpeResult::Ok(ov) => {
                assert_eq!(ov["ipeVersion"], "hub");
                assert_eq!(ov["bufferLogUsed"], 1);
                assert_eq!(ov["bufferTraceUsed"], 2);
                assert_eq!(ov["requestsTotal"], 3); // 1 log + 0 metric + 2 span
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn identity_is_empty() {
        let res: IpeResult<String, Value> = hub_current_identity("anything".to_string()).await;
        match res {
            IpeResult::Ok(id) => {
                assert_eq!(id["subject"], "");
                assert_eq!(id["email"], "");
                assert!(id["claims"].is_object());
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
    }

    #[tokio::test]
    async fn service_stats_aggregates_recent() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-stats-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        // Two recent logs (one error) for service 'svc' → errorRate 0.5 → "err".
        let now = chrono::Utc::now().to_rfc3339();
        for lvl in ["info", "error"] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES ('svc', ?, ?, 'm', '{\"latency_ms\":\"10\"}')",
            )
            .bind(&now)
            .bind(lvl)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<Value>> = hub_read_service_stats(path.clone()).await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["name"], "svc");
                assert_eq!(rows[0]["status"], "err"); // 50% error rate
                assert_eq!(rows[0]["errorRate"], 0.5);
                assert_eq!(rows[0]["p95Ms"], 10.0);
                assert!(rows[0]["sparkRps"].as_array().unwrap().len() == STATS_BUCKET_COUNT);
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    // ─── §5 Class-7 spec: tenant-prefix SQL enforcement ────────────────────

    fn tenant(prefix: &str) -> TenantPrefix {
        TenantPrefix::new(prefix).expect("non-empty test prefix")
    }

    #[test]
    fn reject_cross_tenant_svc_table() {
        let t = tenant("tenant-");
        assert_eq!(reject_cross_tenant_svc("", Some(&t)), Ok(String::new()));
        assert_eq!(
            reject_cross_tenant_svc("tenant-foo", Some(&t)),
            Ok("tenant-foo".to_string())
        );
        assert_eq!(reject_cross_tenant_svc("other-foo", Some(&t)), Err(()));
        // Prefix match is strict: bare "tenant" does not start with "tenant-".
        assert_eq!(reject_cross_tenant_svc("tenant", Some(&t)), Err(()));
        // Case-sensitive: "Tenant-foo" is another tenant's service.
        assert_eq!(reject_cross_tenant_svc("Tenant-foo", Some(&t)), Err(()));
        // No tenant in scope → every svc in scope.
        assert_eq!(
            reject_cross_tenant_svc("anything", None),
            Ok("anything".to_string())
        );
    }

    /// The two-tenant regression: a spill DB seeded with rows for
    /// "customer-42-billing" and "customer-99-billing" — querying with tenant
    /// prefix "customer-42-" must return ONLY the customer-42 rows, even
    /// when called with `service = ""` (tenant-only scope, the
    /// `hub_read_logs` / no-explicit-service shape).
    #[tokio::test]
    async fn hub_read_filtered_logs_two_tenants_no_cross_read() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-tenant-2t-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for svc in ["customer-42-billing", "customer-99-billing"] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'info', 'm', '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_filtered_logs(path.clone(), String::new(), TestFilter::none()),
        )
        .await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(
                    rows.len(),
                    1,
                    "expected exactly the customer-42 row: {rows:?}"
                );
                assert_eq!(rows[0]["subapp"], "customer-42-billing");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// A `hub_read_logs` (no explicit `service`) call under a tenant scope must
    /// ALSO be tenant-filtered — otherwise a tenant-scoped session could bypass
    /// `hub_read_filtered_logs`'s gate simply by calling the no-service kernel.
    #[tokio::test]
    async fn hub_read_logs_no_service_still_tenant_scoped() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-tenant-noservice-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for svc in ["customer-42-billing", "customer-99-billing"] {
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'info', 'm', '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
        }
        let res: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_logs(path.clone(), TestFilter::none()),
        )
        .await;
        match res {
            IpeResult::Ok(rows) => {
                assert_eq!(
                    rows.len(),
                    1,
                    "hub_read_logs must NOT leak other tenants' rows: {rows:?}"
                );
                assert_eq!(rows[0]["subapp"], "customer-42-billing");
            }
            IpeResult::Err(_) => panic!("expected Ok"),
        }
        let _ = std::fs::remove_file(&path);
    }

    /// An explicit cross-tenant `service` argument must be rejected with `Err`
    /// BEFORE any SQL runs — never silently dropped/widened to an unscoped
    /// read, and never leak a cross-tenant row even in the Err path.
    #[tokio::test]
    async fn hub_read_filtered_logs_rejects_explicit_cross_tenant_svc() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-tenant-reject-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        sqlx::query(
            "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
             VALUES ('customer-99-billing', '2026-01-01T00:00:00Z', 'info', 'm', '{}')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let res: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_filtered_logs(
                path.clone(),
                "customer-99-billing".to_string(),
                TestFilter::none(),
            ),
        )
        .await;
        assert!(
            matches!(res, IpeResult::Err(_)),
            "cross-tenant service must be rejected: {res:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Sibling of the two-tenant logs regression, for metrics/traces/errors —
    /// confirms the tenant gate was wired into all four `read_*_value`
    /// builders, not just logs.
    #[tokio::test]
    async fn hub_read_filtered_metrics_traces_errors_scope_to_tenant() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("hub-tenant-mte-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = seed(&path).await;
        for svc in ["customer-42-billing", "customer-99-billing"] {
            sqlx::query(
                "INSERT INTO telemetry_metric (service_name, time, name, type, value, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'reqs', 'counter', 1.0, '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO telemetry_span (service_name, time, name, trace_id, span_id, \
                 parent_id, start_time, end_time, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'op', 't', 's', '', '', '', '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'error', 'boom', '{}')",
            )
            .bind(svc)
            .execute(&pool)
            .await
            .unwrap();
        }

        let metrics: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_filtered_metrics(path.clone(), String::new()),
        )
        .await;
        assert!(matches!(&metrics, IpeResult::Ok(rows) if rows.len() == 1));

        let traces: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_filtered_traces(path.clone(), String::new()),
        )
        .await;
        assert!(matches!(&traces, IpeResult::Ok(rows) if rows.len() == 1));

        let errors: IpeResult<String, Vec<Value>> = with_tenant_prefix(
            tenant("customer-42-"),
            hub_read_filtered_errors(path.clone(), String::new()),
        )
        .await;
        assert!(matches!(&errors, IpeResult::Ok(rows) if rows.len() == 1));

        let _ = std::fs::remove_file(&path);
    }

    /// Refusals of the tenant-scope predicate against a real SQLite spill.
    #[cfg(not(target_arch = "wasm32"))]
    mod tenant_prefix {
        use super::*;

        /// Services whose names collide under `LIKE` semantics: case folding
        /// (`Acme-b`), `_` as a one-character wildcard (`a_b-d` vs `ab-c`), and
        /// `%` as an any-run wildcard (`%x`).
        const SERVICES: [&str; 5] = ["acme-a", "Acme-b", "ab-c", "a_b-d", "%x"];

        /// Create a spill holding one log, error log, metric and span per service.
        async fn seed_spill(name: &str) -> String {
            let path = crate::scratch_core::test_temp_root()
                .join(format!("hub-tenant-{name}-{}.db", std::process::id()))
                .to_string_lossy()
                .to_string();
            let _ = std::fs::remove_file(&path);
            let pool = seed(&path).await;
            for svc in SERVICES {
                sqlx::query(
                    "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'error', ?, '{}')",
                )
                .bind(svc)
                .bind(svc)
                .execute(&pool)
                .await
                .expect("insert log");
                sqlx::query(
                    "INSERT INTO telemetry_metric (service_name, time, name, type, value, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', ?, 'counter', 1.0, '{}')",
                )
                .bind(svc)
                .bind(svc)
                .execute(&pool)
                .await
                .expect("insert metric");
                sqlx::query(
                    "INSERT INTO telemetry_span (service_name, time, name, trace_id, span_id, \
                 parent_id, start_time, end_time, attrs) \
                 VALUES (?, '2026-01-01T00:00:00Z', 'op', 't', 's', '', '', '', '{}')",
                )
                .bind(svc)
                .execute(&pool)
                .await
                .expect("insert span");
            }
            pool.close().await;
            path
        }

        /// The service column of each row, sorted.
        fn services_of(res: &IpeResult<String, Vec<Value>>, key: &str) -> Vec<String> {
            let IpeResult::Ok(rows) = res else {
                return vec!["<Err>".to_string()];
            };
            let mut out: Vec<String> = rows
                .iter()
                .map(|r| r[key].as_str().unwrap_or("<missing>").to_string())
                .collect();
            out.sort();
            out
        }

        /// Every no-service reader under `prefix`, as `(reader, services seen)`.
        async fn scoped_reads(path: &str, prefix: &str) -> Vec<(&'static str, Vec<String>)> {
            let t = TenantPrefix::new(prefix).expect("non-empty test prefix");
            let logs: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                t.clone(),
                hub_read_logs(path.to_string(), TestFilter::none()),
            )
            .await;
            let metrics: IpeResult<String, Vec<Value>> =
                with_tenant_prefix(t.clone(), hub_read_metrics(path.to_string())).await;
            let traces: IpeResult<String, Vec<Value>> =
                with_tenant_prefix(t.clone(), hub_read_traces(path.to_string())).await;
            let errors: IpeResult<String, Vec<Value>> =
                with_tenant_prefix(t, hub_read_errors(path.to_string())).await;
            vec![
                ("logs", services_of(&logs, "subapp")),
                ("metrics", services_of(&metrics, "name")),
                ("traces", services_of(&traces, "kind")),
                ("errors", services_of(&errors, "message")),
            ]
        }

        async fn assert_scope(name: &str, prefix: &str, expected: &[&str]) {
            let path = seed_spill(name).await;
            let expected: Vec<String> = expected.iter().map(ToString::to_string).collect();
            for (reader, seen) in scoped_reads(&path, prefix).await {
                assert_eq!(seen, expected, "{reader} under tenant prefix {prefix:?}");
            }
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn empty_prefix_is_no_tenant() {
            assert_eq!(TenantPrefix::new(""), None);
            assert_eq!(TenantPrefix::new(String::new()), None);
            assert_eq!(
                TenantPrefix::new("%").map(|t| t.as_str().to_string()),
                Some("%".to_string())
            );
        }

        #[tokio::test]
        async fn prefix_is_case_sensitive() {
            assert_scope("case", "acme", &["acme-a"]).await;
        }

        #[tokio::test]
        async fn underscore_is_literal() {
            assert_scope("underscore", "a_b", &["a_b-d"]).await;
        }

        #[tokio::test]
        async fn percent_is_literal() {
            assert_scope("percent", "%", &["%x"]).await;
        }

        #[tokio::test]
        async fn wildcard_only_prefix_matches_nothing_else() {
            assert_scope("wild", "_", &[]).await;
            assert_scope("wildrun", "%_%", &[]).await;
        }

        #[tokio::test]
        async fn explicit_service_outside_prefix_refuses() {
            let path = seed_spill("explicit").await;
            let t = TenantPrefix::new("a_b").expect("non-empty test prefix");
            for svc in ["ab-c", "acme-a", "%x"] {
                let logs: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                    t.clone(),
                    hub_read_filtered_logs(path.clone(), svc.to_string(), TestFilter::none()),
                )
                .await;
                assert!(matches!(logs, IpeResult::Err(_)), "logs {svc:?}: {logs:?}");
                let metrics: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                    t.clone(),
                    hub_read_filtered_metrics(path.clone(), svc.to_string()),
                )
                .await;
                assert!(
                    matches!(metrics, IpeResult::Err(_)),
                    "metrics {svc:?}: {metrics:?}"
                );
                let traces: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                    t.clone(),
                    hub_read_filtered_traces(path.clone(), svc.to_string()),
                )
                .await;
                assert!(
                    matches!(traces, IpeResult::Err(_)),
                    "traces {svc:?}: {traces:?}"
                );
                let errors: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                    t.clone(),
                    hub_read_filtered_errors(path.clone(), svc.to_string()),
                )
                .await;
                assert!(
                    matches!(errors, IpeResult::Err(_)),
                    "errors {svc:?}: {errors:?}"
                );
            }
            let inside: IpeResult<String, Vec<Value>> = with_tenant_prefix(
                t,
                hub_read_filtered_logs(path.clone(), "a_b-d".to_string(), TestFilter::none()),
            )
            .await;
            assert_eq!(services_of(&inside, "subapp"), vec!["a_b-d".to_string()]);
            let _ = std::fs::remove_file(&path);
        }

        /// The service list, the per-service stats and the overview counts are
        /// tenant reads too: none may name or count another tenant's service.
        #[tokio::test]
        async fn service_list_stats_and_overview_are_scoped() {
            let path = seed_spill("aggregate").await;
            let t = TenantPrefix::new("a_b").expect("non-empty test prefix");
            let listed: IpeResult<String, Vec<String>> =
                with_tenant_prefix(t.clone(), hub_list_services(path.clone())).await;
            assert!(
                matches!(&listed, IpeResult::Ok(v) if v == &["a_b-d".to_string()]),
                "listServices: {listed:?}"
            );
            let stats: IpeResult<String, Vec<Value>> =
                with_tenant_prefix(t.clone(), hub_read_service_stats(path.clone())).await;
            assert_eq!(services_of(&stats, "name"), vec!["a_b-d".to_string()]);
            let overview: IpeResult<String, Value> =
                with_tenant_prefix(t, hub_read_overview(path.clone())).await;
            let IpeResult::Ok(ov) = overview else {
                panic!("overview: {overview:?}");
            };
            assert_eq!(ov["bufferLogUsed"], 1, "overview {ov}");
            assert_eq!(ov["bufferTraceUsed"], 1, "overview {ov}");
            assert_eq!(ov["requestsTotal"], 3, "overview {ov}");
            let unscoped: IpeResult<String, Vec<String>> = hub_list_services(path.clone()).await;
            assert!(
                matches!(&unscoped, IpeResult::Ok(v) if v.len() == SERVICES.len()),
                "unscoped listServices: {unscoped:?}"
            );
            let _ = std::fs::remove_file(&path);
        }

        #[tokio::test]
        async fn no_tenant_reads_every_service() {
            let path = seed_spill("none").await;
            let logs: IpeResult<String, Vec<Value>> =
                hub_read_logs(path.clone(), TestFilter::none()).await;
            let mut all: Vec<String> = SERVICES.iter().map(ToString::to_string).collect();
            all.sort();
            assert_eq!(services_of(&logs, "subapp"), all);
            let _ = std::fs::remove_file(&path);
        }
    }
}

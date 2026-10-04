//! Telemetry spill — write-through persistence to a SQLite file.
//!
//! When `IPE_CONSOLE_DB_PATH` is set, the always-compiled in-RAM sink
//! (`telemetry.rs`) ALSO dual-writes every log + span to a SQLite file via a
//! background batcher task. The bundled console child reads that
//! same file through the `hub_*` kernels — so this module + `web/hub.rs`
//! are the two halves of one data layer. The schema is the **hub schema** the
//! hub read kernels expect; the embedded console uses one schema end-to-end.
//!
//! ## Tokio-free core (the load-bearing constraint)
//!
//! `telemetry.rs` is always-compiled, pure-sync, tokio-free. All async / sqlx /
//! tokio machinery lives HERE behind `#[cfg(feature = "db")]`; `record_log` /
//! `record_span` call a cfg-dispatched `spill_offer_*` hook that is a no-op stub
//! when `db` is off. So enabling the spill never forces tokio onto a CLI/Tui
//! program.
//!
//! ## No panic vectors / never poisons the hot path
//!
//! `offer_*` is a non-blocking `try_send`; a full queue drops the entry (the
//! observability surface must never block or panic the request path.
//! Pool-open / schema / write failures degrade to an `eprintln` warn; the in-RAM
//! sink keeps serving. No `unwrap`/`expect`/indexing in any reachable path.

use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use std::sync::OnceLock;
use tokio::sync::mpsc;

/// Env var that turns the spill on .
const SPILL_ENV: &str = "IPE_CONSOLE_DB_PATH";
/// Service-name env (the hub schema groups by `service_name`).
const SERVICE_ENV: &str = "IPE_SERVICE_NAME";
/// Bounded queue depth (~1 s of telemetry at peak; overflow drops + warns).
const QUEUE_CAP: usize = 1024;
/// Retention: logs/spans older than this are pruned hourly .
const RETENTION_HOURS: i64 = 24;

/// Hub schema (the columns `live/hub.rs` reads). Created on enable.
const SPILL_SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS telemetry_log (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT NOT NULL DEFAULT 'unknown', \
    time TEXT NOT NULL, level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL DEFAULT '', \
    trace_id TEXT NOT NULL DEFAULT '', span_id TEXT NOT NULL DEFAULT '', attrs TEXT NOT NULL DEFAULT '{}');\
CREATE TABLE IF NOT EXISTS telemetry_metric (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT NOT NULL DEFAULT 'unknown', \
    time TEXT NOT NULL, name TEXT NOT NULL, type TEXT NOT NULL DEFAULT 'gauge', value REAL NOT NULL, \
    attrs TEXT NOT NULL DEFAULT '{}');\
CREATE TABLE IF NOT EXISTS telemetry_span (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, service_name TEXT NOT NULL DEFAULT 'unknown', \
    time TEXT NOT NULL, name TEXT NOT NULL, trace_id TEXT NOT NULL DEFAULT '', \
    span_id TEXT NOT NULL DEFAULT '', parent_id TEXT NOT NULL DEFAULT '', \
    start_time TEXT NOT NULL, end_time TEXT NOT NULL, attrs TEXT NOT NULL DEFAULT '{}');\
CREATE INDEX IF NOT EXISTS idx_log_service_time ON telemetry_log (service_name, time DESC);\
CREATE INDEX IF NOT EXISTS idx_span_service_time ON telemetry_span (service_name, time DESC);";

/// One record queued for the batcher.
enum SpillEntry {
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
}

static SENDER: OnceLock<mpsc::Sender<SpillEntry>> = OnceLock::new();

/// Whether the local spill writer is active (db parent with `IPE_CONSOLE_DB_PATH`
/// set). The console mount uses this to decide between writing the store
/// directly (db parent) and the push-to-collector path (lean parent pushes to
/// the console child).
pub fn is_enabled() -> bool {
    SENDER.get().is_some()
}

fn service_name() -> String {
    match crate::system::read_env_var(SERVICE_ENV) {
        Ok(s) if !s.is_empty() => s,
        _ => "app".to_string(),
    }
}

fn rfc3339(ts_ms: u64) -> String {
    // Fall back to `now` rather than "" on an out-of-range ts: an empty `time`
    // column sorts before every real row and would never satisfy `time < cutoff`
    // with a real cutoff in a prunable way — making a bad row un-prunable. `now`
    // keeps the row bounded by the same retention window. (Unreachable for real
    // u64 ms timestamps; this is a belt-and-braces total fallback.)
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ts_ms as i64)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339())
}

/// Enable the spill from `IPE_CONSOLE_DB_PATH`. Idempotent + best-effort: a
/// missing env var or any open/schema failure leaves the in-RAM sink untouched.
/// Call once from the runtime entry boot path (db-gated).
pub async fn enable_from_env() {
    let path = match crate::system::read_env_var(SPILL_ENV) {
        Ok(p) if !p.is_empty() => p,
        _ => return,
    };
    if SENDER.get().is_some() {
        return; // already enabled
    }
    let pool = match open_spill_pool(&path).await {
        Ok(p) => p,
        Err(e) => {
            crate::system::emit_runtime_log("spill", &format!("open {path}: {e}"));
            return;
        }
    };
    for stmt in SPILL_SCHEMA.split(';').filter(|s| !s.trim().is_empty()) {
        if let Err(e) = sqlx::query(stmt).execute(&pool).await {
            crate::system::emit_runtime_log("spill", &format!("schema: {e}"));
            return;
        }
    }
    let (tx, rx) = mpsc::channel::<SpillEntry>(QUEUE_CAP);
    if SENDER.set(tx).is_err() {
        return; // lost an enable race; the other winner owns the batcher
    }
    let svc = service_name();
    tokio::spawn(batcher(pool.clone(), rx, svc));
    tokio::spawn(pruner(pool));
}

/// Write one entry to the spill (the unit of work the batcher repeats). Mapping
/// to the hub schema lives here so it's directly testable without the channel.
/// Open (creating it when absent) the spill file at `path` in WAL mode.
///
/// Every connection carries [`crate::system::SQLITE_BUSY_TIMEOUT`] from its connect
/// options. WAL is the only journal mode that lets the console child read while
/// this process writes without each blocking the other; the console reader opens
/// read-write to attach the `-wal`/`-shm` files (`web/hub.rs::open_spill`).
async fn open_spill_pool(path: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .busy_timeout(crate::system::SQLITE_BUSY_TIMEOUT);
    let pool = SqlitePool::connect_with(options).await?;
    let _ = sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await;
    Ok(pool)
}

async fn write_entry(pool: &SqlitePool, svc: &str, entry: SpillEntry) -> Result<(), sqlx::Error> {
    match entry {
        SpillEntry::Log {
            ts_ms,
            level,
            message,
        } => sqlx::query(
            "INSERT INTO telemetry_log (service_name, time, level, message, attrs) \
                 VALUES (?, ?, ?, ?, '{}')",
        )
        .bind(svc)
        .bind(rfc3339(ts_ms))
        .bind(level)
        .bind(message)
        .execute(pool)
        .await
        .map(|_| ()),
        SpillEntry::Span {
            ts_ms,
            name,
            dur_us,
            ok,
        } => {
            let start = rfc3339(ts_ms);
            let end = rfc3339(ts_ms.saturating_add(dur_us / 1000));
            // Hand-built (no serde_json): the `db` feature doesn't pull serde_json,
            // and a db-without-json program (e.g. a Db CLI) must still compile this
            // always-`db`-gated module. The status value is a fixed literal.
            let attrs = format!(r#"{{"status":"{}"}}"#, if ok { "ok" } else { "error" });
            sqlx::query(
                "INSERT INTO telemetry_span (service_name, time, name, start_time, end_time, attrs) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(svc)
            .bind(&start)
            .bind(name)
            .bind(&start)
            .bind(end)
            .bind(attrs)
            .execute(pool)
            .await
            .map(|_| ())
        }
    }
}

/// Drain the queue and write each entry. A failed write warns + continues (the
/// hot path already succeeded into the in-RAM ring).
async fn batcher(pool: SqlitePool, mut rx: mpsc::Receiver<SpillEntry>, svc: String) {
    while let Some(entry) = rx.recv().await {
        if let Err(e) = write_entry(&pool, &svc, entry).await {
            crate::system::emit_runtime_log("spill", &format!("write: {e}"));
        }
    }
}

/// Hourly TTL prune (logs + spans older than RETENTION_HOURS).
async fn pruner(pool: SqlitePool) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::hours(RETENTION_HOURS)).to_rfc3339();
        for table in ["telemetry_log", "telemetry_span"] {
            let sql = format!("DELETE FROM {table} WHERE time < ?");
            if let Err(e) = sqlx::query(&sql).bind(&cutoff).execute(&pool).await {
                crate::system::emit_runtime_log("spill", &format!("prune {table}: {e}"));
            }
        }
        // Bound the -wal file: under sustained writes WAL mode lets the -wal grow
        // unbounded between automatic checkpoints. A TRUNCATE checkpoint after the
        // hourly prune resets it to zero bytes (best-effort — a long-lived reader
        // holding back the checkpoint just defers it to the next tick, never blocks).
        if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&pool)
            .await
        {
            crate::system::emit_runtime_log("spill", &format!("wal_checkpoint: {e}"));
        }
    }
}

/// Non-blocking offer of a log to the spill. No-op when disabled or the queue
/// is full (drop — never block/panic the caller). Called from `record_log`.
pub fn offer_log(ts_ms: u64, level: &str, message: &str) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(SpillEntry::Log {
            ts_ms,
            level: level.to_string(),
            message: message.to_string(),
        });
    }
}

/// Non-blocking offer of a span to the spill. Called from `record_span`.
pub fn offer_span(ts_ms: u64, name: &str, dur_us: u64, ok: bool) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(SpillEntry::Span {
            ts_ms,
            name: name.to_string(),
            dur_us,
            ok,
        });
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "web")]
    use super::super::core::IpeResult;
    use super::*;
    use sqlx::Row;

    /// The batcher's unit of work mapped onto the hub schema — schema creation +
    /// INSERT (logs + spans) + field derivation, read back on one pool. Verifies
    /// the write/mapping deterministically (the channel + spawn plumbing around
    /// it is trivial). Cross-process visibility is a standard SQLite guarantee.
    #[tokio::test]
    async fn write_entry_maps_to_hub_schema() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("spill-we-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = SqlitePool::connect(&format!("sqlite:{path}?mode=rwc"))
            .await
            .expect("create spill");
        for stmt in SPILL_SCHEMA.split(';').filter(|s| !s.trim().is_empty()) {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }

        write_entry(
            &pool,
            "tsvc",
            SpillEntry::Log {
                ts_ms: 1_700_000_000_000,
                level: "error".into(),
                message: "spilled boom".into(),
            },
        )
        .await
        .unwrap();
        write_entry(
            &pool,
            "tsvc",
            SpillEntry::Span {
                ts_ms: 1_700_000_000_000,
                name: "db.query".into(),
                dur_us: 5000,
                ok: true,
            },
        )
        .await
        .unwrap();

        let lr = sqlx::query("SELECT service_name, level, message FROM telemetry_log LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(lr.try_get::<String, _>("service_name").unwrap(), "tsvc");
        assert_eq!(lr.try_get::<String, _>("level").unwrap(), "error");
        assert_eq!(lr.try_get::<String, _>("message").unwrap(), "spilled boom");

        let sr = sqlx::query(
            "SELECT service_name, name, start_time, end_time, attrs FROM telemetry_span LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(sr.try_get::<String, _>("name").unwrap(), "db.query");
        assert_eq!(sr.try_get::<String, _>("service_name").unwrap(), "tsvc");
        // 5000us = 5ms → end = start + 5ms; attrs carries ok→status.
        assert!(
            sr.try_get::<String, _>("attrs")
                .unwrap()
                .contains("\"status\":\"ok\"")
        );
        assert_ne!(
            sr.try_get::<String, _>("start_time").unwrap(),
            sr.try_get::<String, _>("end_time").unwrap()
        );

        // The reader (open_spill mode=rw) sees the same rows — the read↔write
        // contract end-to-end. `hub_list_services` is a `live`-gated reader, so
        // this leg only runs when `live` is compiled in (a `db`-only build has
        // no hub); the write/mapping asserts above hold in either configuration.
        #[cfg(feature = "web")]
        {
            let n: IpeResult<String, Vec<String>> =
                super::super::web::hub::hub_list_services(path.clone()).await;
            assert!(
                matches!(n, IpeResult::Ok(ref v) if v == &vec!["tsvc".to_string()]),
                "{n:?}"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Every connection the spill pool hands out at once carries the declared
    /// busy timeout.
    #[tokio::test]
    async fn the_spill_pool_carries_the_declared_busy_timeout() {
        let path = crate::scratch_core::test_temp_root()
            .join(format!("spill-busy-{}.db", std::process::id()))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_file(&path);
        let pool = open_spill_pool(&path).await.expect("open spill");
        let expected = i64::try_from(crate::system::SQLITE_BUSY_TIMEOUT.as_millis())
            .expect("timeout fits i64");
        let size = pool.options().get_max_connections();
        let mut held = Vec::new();
        for _ in 0..size {
            held.push(pool.acquire().await.expect("acquire spill connection"));
        }
        assert!(
            held.len() > 1,
            "the spill pool holds more than one connection"
        );
        for conn in &mut held {
            let ms = sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout")
                .fetch_one(&mut **conn)
                .await
                .expect("read busy_timeout");
            assert_eq!(ms, expected);
        }
        drop(held);
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    #[test]
    fn offer_without_enable_is_noop() {
        // offer_* must never panic regardless of SENDER state.
        offer_log(0, "info", "ignored");
        offer_span(0, "noop", 0, true);
    }
}

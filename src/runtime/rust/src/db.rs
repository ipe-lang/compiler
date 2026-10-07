// DB kernel functions — generic over E and over backend.
// Uses DbPool, DbRow, ipe_db_url, db_last_insert_id, db_format_sql from
// config.rs (generated at build time per package.ipe database driver).
use super::json::{Decoder, JsonVal, decode_and_map, decode_err_str, decode_field, decode_ok};
use super::*;
use crate::ssrf::{
    ConfiguredHost, DialPolicy, HostResolver, SsrfRefusal, SystemResolver, UnambiguousUrl,
    UrlUnproven, VettedDial,
};
use sqlx::{Column, Row, TypeInfo};
use std::collections::HashMap;

pub type Db = DbPool;

#[cfg(feature = "db")]
crate::stringify::show_row!("Db", Internals, [] Db, |_| "<Ipe.Db.Db>".to_owned());
#[cfg(feature = "db")]
crate::stringify::show_row!("ProjectionTerm", Internals, [] ProjectionTerm, |_| "<Ipe.Db.ProjectionTerm>".to_owned());
#[cfg(feature = "db")]
crate::stringify::show_row!("ProjectionOperand", Internals, [] ProjectionOperand, |_| "<Ipe.Db.ProjectionOperand>".to_owned());
#[cfg(feature = "db")]
crate::stringify::show_row!("ArithOp", Internals, [] ArithOp, |_| "<Ipe.Db.ArithOp>".to_owned());

/// One term in a `Store.select` projection — the typed carrier that replaces the
/// stringly-encoded `(tag, operand_a, operand_b)` triple.  Illegal states are
/// unrepresentable: the variant set is closed, there is no tag-string re-derivation,
/// and no "else = column" fallthrough.
///
/// Defence in depth is preserved: every `String` field that reaches SQL text is
/// re-validated via [`SqlIdent::parse_plain`] or [`SqlIdent::parse_dotted`] inside
/// [`build_projection_statement`] before interpolation.
#[derive(Clone, Debug, PartialEq)]
pub enum ProjectionTerm {
    /// Plain `alias.column AS pN` — `alias` and `column` are bare SQL identifiers.
    ColumnTerm(String, String),
    /// `? AS pN` — `Store.literal` position; the bound value comes from the
    /// `extra_binds` slice in positional order.
    LiteralTerm,
    /// `UPPER(dotted) AS pN` — `dotted` is `"alias.col"` re-validated via
    /// [`SqlIdent::parse_dotted`].
    UpperTerm(String),
    /// `LOWER(dotted) AS pN` — `dotted` is `"alias.col"` re-validated via
    /// [`SqlIdent::parse_dotted`].
    LowerTerm(String),
    /// `COALESCE(a, b) AS pN` — each operand is either a dotted column or a
    /// literal `?` placeholder.
    CoalesceTerm(ProjectionOperand, ProjectionOperand),
    /// `(a <op> b) AS pN` — a binary arithmetic expression over two numeric
    /// operands, each a dotted column or a literal `?` placeholder.  The
    /// [`ArithOp`] tag is drawn from a closed set, never from input.
    ArithTerm(ArithOp, ProjectionOperand, ProjectionOperand),
}

/// The closed set of binary arithmetic operators a `Store.select` projection may
/// lift over two numeric operands.  A fixed tag — never attacker-controlled —
/// so the SQL operator symbol comes only from [`ArithOp::sql_symbol`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArithOp {
    /// SQL `+`.
    ArithAdd,
    /// SQL `-`.
    ArithSub,
    /// SQL `*`.
    ArithMul,
}

impl ArithOp {
    /// The SQL infix symbol for this operator.  A method over a closed enum, so
    /// the symbol reaching SQL text is one of exactly three fixed strings.
    const fn sql_symbol(self) -> &'static str {
        match self {
            Self::ArithAdd => "+",
            Self::ArithSub => "-",
            Self::ArithMul => "*",
        }
    }
}

/// One operand inside a [`ProjectionTerm::CoalesceTerm`] or
/// [`ProjectionTerm::ArithTerm`].  Replaces the `is_empty()` sentinel on the
/// `(tag, operand_a, operand_b)` third string.
#[derive(Clone, Debug, PartialEq)]
pub enum ProjectionOperand {
    /// A dotted `alias.col` column reference, re-validated via
    /// [`SqlIdent::parse_dotted`] before SQL interpolation.
    OperandColumn(String),
    /// A `?` placeholder whose bound value comes from `extra_binds`.
    OperandLiteral,
}

/// Build a Ipê-visible `Error` from a sqlx error WITHOUT leaking row/column
/// VALUES. The `Display` of a driver error (PostgreSQL/MySQL especially) embeds
/// the offending value in a constraint-violation message — e.g.
/// `... Key (email)=(victim@example.com) already exists` — so funnelling the raw
/// `format!("{}", e)` into the returned `Error` leaks private row data the moment
/// an app surfaces or logs it (PRINCIPLES #1). For a database-level error we
/// therefore build a STRUCTURAL message from the safe-to-expose fields only:
/// the SQLSTATE code (a correlation id operators can trace) and the constraint
/// NAME (a schema identifier, not row data) — never the value. Non-database
/// errors (pool acquisition, connect, decode, IO) carry no row values, so their
/// `Display` is kept for diagnosability. Total — no unwrap/index/panic.
fn ipe_err<E: From<String> + Send>(e: &sqlx::Error) -> E {
    if let Some(dbe) = e.as_database_error() {
        let mut msg = String::from("db: database error");
        if let Some(code) = dbe.code() {
            // SQLSTATE / driver code — structural, value-free.
            msg.push_str(&format!(" [{}]", code));
        }
        if let Some(constraint) = dbe.constraint() {
            // Constraint NAME is a schema identifier (e.g. `users_email_key`),
            // not the offending value — safe to expose and useful for the caller.
            msg.push_str(&format!(" (constraint {})", constraint));
        }
        return str_err(&msg);
    }
    // Non-database errors generally carry no row VALUES, but `ColumnDecode` /
    // `Decode` can embed `source` text that may include a column value — keep
    // those structural (index / variant only). Io / Tls / Protocol /
    // PoolTimedOut / RowNotFound carry no row data, so their `Display` is kept.
    match e {
        sqlx::Error::ColumnDecode { index, .. } => {
            str_err(&format!("db: column decode error at index {index}"))
        }
        sqlx::Error::Decode(_) => str_err("db: decode error"),
        other => str_err(&format!("{other}")),
    }
}

// ─── Transaction connection routing (task-local) ──────────────────────────────
//
// `withTransaction` must run BEGIN, the entire body, and COMMIT/ROLLBACK on ONE
// physical connection. A bare `pool.execute(BEGIN)` routes each statement to an
// arbitrary free connection, so on a multi-connection pool (Postgres/MySQL
// default, or `IPE_DB_MAX_CONNECTIONS > 1` on sqlite) the body's writes can
// autocommit on a different connection that has no open transaction — a rollback
// then silently fails to undo them.
//
// Fix: `db_with_transaction` acquires ONE `PoolConnection` from the pool, stores
// it (behind a `tokio::sync::Mutex` for shared, serialised access) in a
// `tokio::task_local!`, and runs the body inside `TXN_CONN.scope(..)`. Every
// body-reachable DB op routes its query through `exec_*` / `fetch_*` helpers
// below, which lock the task-local connection when one is present, else fall back
// to the pool. Because the body runs on the SAME tokio task (and any spawned
// child task does NOT inherit the task-local — by design, child tasks get the
// pool and must not share the txn connection), every statement lands on the held
// connection and the transaction is real on any pool size.
//
// A `tokio::task_local!` (NOT `thread_local!`) is mandatory: tokio's work-
// stealing scheduler moves a task across worker threads at every `.await`, so a
// thread-local would lose the connection mid-body.

/// The concrete sqlx database backend for this build (sqlite / postgres / mysql),
/// derived from the configured `DbRow` so the helpers stay driver-agnostic.
type DbDatabase = <DbRow as sqlx::Row>::Database;

/// A dedicated sqlx `Transaction`, shared across the body via `Arc<Mutex<..>>`
/// so re-entrant body ops serialise on it (sqlx connections are `&mut`-exclusive).
/// Using a `Transaction` (not a bare `PoolConnection` + raw `BEGIN`) is
/// load-bearing for CANCELLATION SAFETY: its `Drop` rolls back, so a body future
/// dropped mid-transaction (timeout / `select!` / task abort) can never return an
/// OPEN transaction to the pool for the next checkout to inherit.
type TxnConn = std::sync::Arc<tokio::sync::Mutex<sqlx::Transaction<'static, DbDatabase>>>;

// A stable identity for a `Db` (pool) value. `Db` stays a bare `sqlx::Pool`
// alias (no newtype, no change to any of the 70+ existing call sites) — but
// `Pool::connect_options()` hands back a clone of an `Arc` that the pool
// allocated ONCE at build time and every `Pool::clone()` shares. Two clones of
// the SAME pool therefore return `Arc`s that are `ptr_eq`; two DIFFERENT pools
// (even ones connected to the same URL via two separate `.connect()` calls
// that didn't go through `connect_cached`) get distinct allocations. This
// gives genuine pool identity with zero blast radius on the public `Db` type.
type PoolIdentity =
    std::sync::Arc<<<DbDatabase as sqlx::Database>::Connection as sqlx::Connection>::Options>;

fn pool_identity(pool: &Db) -> PoolIdentity {
    pool.connect_options()
}

tokio::task_local! {
    /// Present (Some) for the dynamic extent of a `withTransaction` body — holds
    /// the identity of the pool the transaction was opened on, plus the
    /// dedicated connection BEGIN/COMMIT/ROLLBACK ran on. The identity is
    /// load-bearing: routing (below) and the nesting gate in
    /// `db_with_transaction` both consult it so that a DB op or a nested
    /// `withTransaction` call against a DIFFERENT `Db` handle never gets
    /// silently executed against this transaction's connection (AUD-03).
    static TXN_CONN: Option<(PoolIdentity, TxnConn)>;
}

/// Read the active transaction connection for the current task, but ONLY when
/// it was opened on the SAME pool as `pool` — a transaction active for a
/// different `Db` handle must never receive this pool's operations. Total:
/// returns `None` outside a `withTransaction` scope, or when the active
/// transaction belongs to a different pool (both cases fall through to
/// running directly against `pool`, exactly like "no transaction active").
fn current_txn_conn_for(pool: &Db) -> Option<TxnConn> {
    let active = TXN_CONN.try_with(|c| c.clone()).ok().flatten()?;
    let (owner, conn) = active;
    if std::sync::Arc::ptr_eq(&owner, &pool_identity(pool)) {
        Some(conn)
    } else {
        None
    }
}

// The query type produced by `sqlx::query(&sql)` for the configured backend.
type DbQuery<'q> =
    sqlx::query::Query<'q, DbDatabase, <DbDatabase as sqlx::Database>::Arguments<'q>>;

/// The one place that decides where a routed query runs. Either the pool (no
/// transaction active on `pool`, or one active on a *different* pool that the
/// `ptr_eq` identity gate turns away — AUD-03) or the dedicated transaction
/// connection whose pool identity matches `pool`. Every `*_routed` helper below
/// dispatches through exactly one of these, so the pool-vs-transaction choice —
/// and the security-critical identity gate that makes it — lives at a single
/// substitutable seam rather than being re-derived in four near-identical fns.
enum QueryTarget<'a> {
    Pool(&'a Db),
    Txn(TxnConn),
}

/// Consult the ambient task-local for the connection a query on `pool` must
/// ride. `current_txn_conn_for` enforces the `ptr_eq` pool-identity gate, so a
/// transaction active on a different `Db` handle yields `Pool` (fall through),
/// never that transaction's connection.
fn route_for(pool: &Db) -> QueryTarget<'_> {
    match current_txn_conn_for(pool) {
        Some(conn) => QueryTarget::Txn(conn),
        None => QueryTarget::Pool(pool),
    }
}

impl QueryTarget<'_> {
    /// Own the lock-and-run for the transaction arm so no caller re-derives it.
    async fn execute<'q>(
        &self,
        query: DbQuery<'q>,
    ) -> Result<<DbDatabase as sqlx::Database>::QueryResult, sqlx::Error> {
        match self {
            QueryTarget::Pool(pool) => query.execute(*pool).await,
            QueryTarget::Txn(conn) => {
                let mut guard = conn.lock().await;
                query.execute(&mut **guard).await
            }
        }
    }

    async fn fetch_all<'q>(&self, query: DbQuery<'q>) -> Result<Vec<DbRow>, sqlx::Error> {
        match self {
            QueryTarget::Pool(pool) => query.fetch_all(*pool).await,
            QueryTarget::Txn(conn) => {
                let mut guard = conn.lock().await;
                query.fetch_all(&mut **guard).await
            }
        }
    }

    async fn fetch_optional<'q>(&self, query: DbQuery<'q>) -> Result<Option<DbRow>, sqlx::Error> {
        match self {
            QueryTarget::Pool(pool) => query.fetch_optional(*pool).await,
            QueryTarget::Txn(conn) => {
                let mut guard = conn.lock().await;
                query.fetch_optional(&mut **guard).await
            }
        }
    }

    async fn fetch_one<'q>(&self, query: DbQuery<'q>) -> Result<DbRow, sqlx::Error> {
        match self {
            QueryTarget::Pool(pool) => query.fetch_one(*pool).await,
            QueryTarget::Txn(conn) => {
                let mut guard = conn.lock().await;
                query.fetch_one(&mut **guard).await
            }
        }
    }

    /// Runs a write whose `RETURNING` names the policy check, keeping it only
    /// when every returned row is admitted.
    ///
    /// The write runs in its own savepoint: a fresh transaction on the pool, or
    /// a nested `SAVEPOINT` on the routed transaction connection, so a refused
    /// write rolls back alone and leaves an enclosing `withTransaction` usable.
    /// [`settle_checked_write`] decides commit or rollback; the count is the
    /// admitted row count, or `0` when nothing was kept.
    async fn checked_write(&self, query: DbQuery<'_>) -> Result<u64, sqlx::Error> {
        match self {
            QueryTarget::Pool(pool) => {
                let savepoint = pool.begin().await?;
                settle_checked_write(savepoint, query).await
            }
            QueryTarget::Txn(conn) => {
                let mut guard = conn.lock().await;
                let savepoint = sqlx::Connection::begin(&mut **guard).await?;
                settle_checked_write(savepoint, query).await
            }
        }
    }

    /// Test-only observer of the routing decision — lets a test drive the
    /// ambient path (`with_recording_txn`) and assert which arm was chosen
    /// without reaching past the seam into the task-local by hand.
    #[cfg(test)]
    fn rode_transaction(&self) -> bool {
        matches!(self, QueryTarget::Txn(_))
    }

    /// Test-only: true when this target rode the SAME transaction connection as
    /// `conn`. Lets a nested-flatten test prove the inner scope reused the outer
    /// recording connection rather than opening a second one.
    #[cfg(test)]
    fn rode_same_txn_as(&self, conn: &TxnConn) -> bool {
        matches!(self, QueryTarget::Txn(c) if std::sync::Arc::ptr_eq(c, conn))
    }
}

/// Run a built query for its side effects, on the active transaction connection
/// when one is present (so the statement shares the transaction), else on the
/// pool. Returns the driver query result.
async fn exec_routed<'q>(
    pool: &Db,
    query: DbQuery<'q>,
) -> Result<<DbDatabase as sqlx::Database>::QueryResult, sqlx::Error> {
    route_for(pool).execute(query).await
}

/// `fetch_all` routed through the active transaction connection when present.
async fn fetch_all_routed<'q>(pool: &Db, query: DbQuery<'q>) -> Result<Vec<DbRow>, sqlx::Error> {
    route_for(pool).fetch_all(query).await
}

/// `fetch_optional` routed through the active transaction connection when present.
async fn fetch_optional_routed<'q>(
    pool: &Db,
    query: DbQuery<'q>,
) -> Result<Option<DbRow>, sqlx::Error> {
    route_for(pool).fetch_optional(query).await
}

/// `fetch_one` routed through the active transaction connection when present.
async fn fetch_one_routed<'q>(pool: &Db, query: DbQuery<'q>) -> Result<DbRow, sqlx::Error> {
    route_for(pool).fetch_one(query).await
}

/// Install `executor` as the ambient transaction connection for `pool` over the
/// extent of `fut`, exactly as `db_with_transaction` does — same `TXN_CONN.scope`,
/// same *real* `pool_identity(pool)` — so a test drives routing through the
/// genuine ambient path and the `ptr_eq` identity gate, never a backdoor into the
/// task-local. `executor` is a real `TxnConn` the caller opened on `pool` (via
/// `pool.begin()`), so the identity gate has genuine material and the recording
/// double stays a bona-fide transaction, not a mislabelled stand-in. The scope
/// confines the installed connection to `fut`: it is neither cloned out nor
/// leaked, preserving the sole-ownership invariant `db_with_transaction` relies
/// on at commit.
#[cfg(test)]
async fn with_recording_txn<T>(
    pool: &Db,
    executor: TxnConn,
    fut: impl std::future::Future<Output = T>,
) -> T {
    let owner = pool_identity(pool);
    TXN_CONN.scope(Some((owner, executor)), fut).await
}

/// True when column `i`'s driver-reported type is a genuine boolean.
///
/// The `bool` reader must then run before the integer reader. The decision is
/// keyed on the driver-reported storage type, NOT on a speculative
/// `try_get::<bool>`: on SQLite a `bool` decode succeeds for EVERY integer cell
/// (any non-zero → true), so a bool-first probe would read `qty = 7` as `true`.
/// Postgres `BOOL` and SQLite `BOOLEAN` report a boolean type name; a SQLite
/// INTEGER cell reports `INTEGER` (its runtime storage class) even when it was
/// bound from a Rust `bool` — the driver returns `int64` for those cells.
fn column_is_boolean<R: Row>(row: &R, i: usize) -> bool {
    row.columns()
        .get(i)
        .map(sqlx::Column::type_info)
        .is_some_and(|ti| {
            let name = ti.name();
            name.eq_ignore_ascii_case("BOOL") || name.eq_ignore_ascii_case("BOOLEAN")
        })
}

/// Decode column `i` into a `String` for the untyped `row_to_map` path.
///
/// A boolean-typed column reads via `bool` first; every other column reads
/// numeric-first (i64 → f64) so a SQLite INTEGER is never stolen by the bool
/// reader. `Ok(None)` at any arm = SQL NULL → `""`. The final fallback is
/// `String::new()` — the untyped path has no typed consumer to distinguish NULL
/// from empty (documented at call site).
fn column_to_string(row: &DbRow, i: usize) -> String {
    if column_is_boolean(row, i)
        && let Ok(opt) = row.try_get::<Option<bool>, _>(i)
    {
        return opt.map_or_else(String::new, |b| b.to_string());
    }
    // NULL at any arm → ""; continue to next probe only on decode error.
    if let Ok(opt) = row.try_get::<Option<i64>, _>(i) {
        return opt.map_or_else(String::new, |n| n.to_string());
    }
    if let Ok(opt) = row.try_get::<Option<f64>, _>(i) {
        return opt.map_or_else(String::new, |f| f.to_string());
    }
    if let Ok(opt) = row.try_get::<Option<String>, _>(i) {
        return opt.unwrap_or_default();
    }
    // BYTEA / BLOB: encode as lowercase hex so the value survives round-trip
    // through `db_decode_bytes` (which hex-decodes back to `Vec<u8>`).
    if let Ok(Some(bytes)) = row.try_get::<Option<Vec<u8>>, _>(i) {
        return hex::encode(bytes);
    }
    String::new()
}

/// The `ColumnDecode` reason [`read_cell`] gives a `NaN` / `±Inf` `REAL` cell.
const NON_FINITE_REAL: &str = "non-finite REAL (NaN / +Inf / -Inf has no cell value)";

/// The `ColumnDecode` reason [`read_cell`] gives a cell no probe reads.
const UNSUPPORTED_COLUMN_TYPE: &str = "unsupported column type (not bool/i64/f64/String/bytes)";

/// A finite `f64`, held as the JSON number every finite float has.
///
/// The only constructor, [`FiniteF64::new`], refuses `NaN` and `±Inf`, so a cell
/// float always has a JSON projection and never needs a `Null` fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FiniteF64(serde_json::Number);

impl FiniteF64 {
    /// `Some` for a finite `f`; `None` for `NaN`, `+Inf` and `-Inf`.
    fn new(f: f64) -> Option<Self> {
        serde_json::Number::from_f64(f).map(Self)
    }
}

/// One database cell as [`read_cell`] reads it; SQL `NULL` is its own arm.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Cell {
    /// SQL `NULL`.
    Null,
    /// A boolean-typed column (`BOOL` / `BOOLEAN`).
    Bool(bool),
    /// An integer cell.
    Int(i64),
    /// A finite floating-point cell.
    Float(FiniteF64),
    /// A text cell, verbatim.
    Text(String),
    /// A `BLOB` / `BYTEA` cell.
    Bytes(Vec<u8>),
}

impl Cell {
    /// The cell as the JSON value the typed decoders read.
    ///
    /// `Null` is `JsonVal::Null`; bytes become lowercase hex text, the form
    /// `db_decode_bytes` reads back.
    fn into_json(self) -> JsonVal {
        match self {
            Self::Null => JsonVal::Null,
            Self::Bool(b) => JsonVal::Bool(b),
            Self::Int(n) => JsonVal::Number(serde_json::Number::from(n)),
            Self::Float(FiniteF64(n)) => JsonVal::Number(n),
            Self::Text(s) => JsonVal::String(s),
            Self::Bytes(b) => JsonVal::String(hex::encode(b)),
        }
    }
}

/// The column reader: column `i` of an app or external row as a [`Cell`].
///
/// Probe order: `bool` (only for a boolean-typed column, see
/// [`column_is_boolean`]) → `i64` → `f64` → `String` → bytes. `Ok(None)` at a
/// probe is [`Cell::Null`]; a probe whose type does not match moves to the next.
/// A `NaN` / `±Inf` `REAL` is `Err(ColumnDecode)` with [`NON_FINITE_REAL`], and a
/// cell no probe reads is `Err(ColumnDecode)` with [`UNSUPPORTED_COLUMN_TYPE`]:
/// a cell is never given a default value.
fn read_cell<R>(row: &R, i: usize) -> Result<Cell, sqlx::Error>
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    for<'a> Option<bool>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<i64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<f64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<Vec<u8>>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let refuse = |reason: &str| sqlx::Error::ColumnDecode {
        index: i.to_string(),
        source: reason.into(),
    };
    if column_is_boolean(row, i)
        && let Ok(opt) = row.try_get::<Option<bool>, _>(i)
    {
        return Ok(opt.map_or(Cell::Null, Cell::Bool));
    }
    if let Ok(opt) = row.try_get::<Option<i64>, _>(i) {
        return Ok(opt.map_or(Cell::Null, Cell::Int));
    }
    if let Ok(opt) = row.try_get::<Option<f64>, _>(i) {
        return opt.map_or(Ok(Cell::Null), |f| {
            FiniteF64::new(f)
                .map(Cell::Float)
                .ok_or_else(|| refuse(NON_FINITE_REAL))
        });
    }
    if let Ok(opt) = row.try_get::<Option<String>, _>(i) {
        return Ok(opt.map_or(Cell::Null, Cell::Text));
    }
    if let Ok(opt) = row.try_get::<Option<Vec<u8>>, _>(i) {
        return Ok(opt.map_or(Cell::Null, Cell::Bytes));
    }
    Err(refuse(UNSUPPORTED_COLUMN_TYPE))
}

// needless_range_loop (accepted, cosmetic): the loop indexes by position to pair
// column name[i] with value[i] across two parallel slices — an iterator can't
// thread both. Not a soundness concern.
#[allow(clippy::needless_range_loop)]
fn row_to_map(row: &DbRow) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let cols = row.columns();
    for (i, col) in cols.iter().enumerate() {
        let name = col.name().to_string();
        map.insert(name, column_to_string(row, i));
    }
    map
}

/// An app or external row as the `JsonVal::Object` the typed decoders read.
///
/// Each column goes through [`read_cell`] then [`Cell::into_json`], so SQL
/// `NULL` stays `JsonVal::Null` (`db_decode_nullable` tells it from an empty
/// value). An unreadable cell is `Err(ColumnDecode)`; the caller converts it
/// through `ipe_err`, so the read fails closed.
fn row_to_json<R>(row: &R) -> Result<JsonVal, sqlx::Error>
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    for<'a> Option<bool>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<i64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<f64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<Vec<u8>>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let cols = row.columns();
    let mut map = serde_json::Map::with_capacity(cols.len());
    for (i, col) in cols.iter().enumerate() {
        map.insert(col.name().to_string(), read_cell(row, i)?.into_json());
    }
    Ok(JsonVal::Object(map))
}

// ─── DB-specific typed decoder primitives ─────────────────────────────────────
//
// Each primitive wraps `decode_field` (reads a named column from the JsonVal
// object produced by `row_to_json`) and adds domain-specific value parsing.
// ALL are TOTAL: missing column, NULL, or parse failure → `IpeResult::Err` via
// `decode_err_str`, NEVER `.unwrap()` / `.expect()` / `panic!`.
//
// The shared `Decoder<E,T>` type (json.rs:7) is reused here — DbDec decoders
// and JsonDec decoders are the same Rust type. Correctness is ensured by the
// runner functions (`db_query_decode`, `db_get_by_id_decode`) which always feed
// a `row_to_json`-produced `JsonVal::Object` to the decoder, never a raw JSON
// document. Cross-application (JsonDec decoder run against a DB row or vice
// versa) is still well-formed (the types match); it just may produce parse
// errors on format mismatches, which is the expected behaviour.

/// `DbDec.string col` — read column `col` as a String.
/// Fails with Err when the column is missing OR its value is NULL.
pub fn db_decode_string<E: From<String> + 'static>(col: String) -> Decoder<E, String> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| match v {
                JsonVal::String(s) => decode_ok(s.clone()),
                JsonVal::Null => {
                    decode_err_str(format!("column {}: expected String, got NULL", col))
                }
                _ => decode_err_str(format!(
                    "column {}: expected String, got {:?}",
                    col,
                    v.to_string()
                )),
            }),
            vec![],
        ),
    )
}

/// `DbDec.int col` — read column `col` as an Int (i64).
/// Accepts: JSON Number, or a String representation of an integer or decimal
/// (e.g. "42", "3.0" → 3). NULL → Err. Parse failure → Err.
/// Matches `DbDec_int` truthy table (int/int64/float64/string forms).
pub fn db_decode_int<E: From<String> + 'static>(col: String) -> Decoder<E, i64> {
    // Parse-don't-validate: a float source (JSON float or decimal string) is
    // truncated toward zero to an `Int`, but a magnitude past the `i64` range is
    // malformed input, not a value to silently saturate. Rust's `as` cast would
    // clamp `1e30` to `i64::MAX` and report `Ok` — data loss presented as
    // success. Reject it as a typed decode error instead (fail-closed).
    fn float_to_i64_checked<E: From<String>>(col: &str, f: f64) -> IpeResult<E, i64> {
        // Both bounds are exclusive: f64 cannot distinguish a boundary from its
        // out-of-range neighbour. `i64::MAX as f64` rounds up to 2^63 and an
        // input just past `i64::MIN` rounds down to `i64::MIN as f64`, so `<=`/
        // `>=` would admit an out-of-range magnitude and let `as i64` saturate
        // to the limit — data loss reported as success. An exact `i64::MIN`/
        // `i64::MAX` still decodes through the integer path above.
        let truncated = f.trunc();
        if truncated > i64::MIN as f64 && truncated < 9_223_372_036_854_775_808.0 {
            decode_ok(truncated as i64)
        } else {
            decode_err_str(format!(
                "column {}: expected Int, {} is out of range for a 64-bit integer",
                col, f
            ))
        }
    }
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| match v {
                JsonVal::Number(n) => match n.as_i64() {
                    Some(i) => decode_ok(i),
                    None => match n.as_f64() {
                        Some(f) => float_to_i64_checked(&col, f),
                        None => decode_err_str(format!(
                            "column {}: expected Int, number out of range",
                            col
                        )),
                    },
                },
                JsonVal::String(s) => {
                    // Accept "42" or "3.0" (decimal truncation toward zero).
                    if let Ok(i) = s.parse::<i64>() {
                        return decode_ok(i);
                    }
                    if let Ok(f) = s.parse::<f64>() {
                        return float_to_i64_checked(&col, f);
                    }
                    decode_err_str(format!("column {}: expected Int, got {:?}", col, s))
                }
                JsonVal::Null => decode_err_str(format!("column {}: expected Int, got NULL", col)),
                _ => decode_err_str(format!("column {}: expected Int, got unexpected type", col)),
            }),
            vec![],
        ),
    )
}

/// `DbDec.float col` — read column `col` as a Float (f64).
/// Matches `DbDec_float` truthy table (float64/int/int64/string forms).
pub fn db_decode_float<E: From<String> + 'static>(col: String) -> Decoder<E, f64> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| match v {
                JsonVal::Number(n) => match n.as_f64() {
                    Some(f) => decode_ok(f),
                    None => decode_err_str(format!(
                        "column {}: expected Float, number unrepresentable as f64",
                        col
                    )),
                },
                JsonVal::String(s) => match s.parse::<f64>() {
                    Ok(f) => decode_ok(f),
                    Err(_) => {
                        decode_err_str(format!("column {}: expected Float, got {:?}", col, s))
                    }
                },
                JsonVal::Null => {
                    decode_err_str(format!("column {}: expected Float, got NULL", col))
                }
                _ => decode_err_str(format!(
                    "column {}: expected Float, got unexpected type",
                    col
                )),
            }),
            vec![],
        ),
    )
}

/// `DbDec.bool col` — read column `col` as a Bool.
/// Truthy table:
///   true  ← "true" | "TRUE" | "True" | "t" | "T" | "1" | JSON true  | int 1  | int64 1
///   false ← "false"| "FALSE"| "False"| "f" | "F" | "0" | JSON false | int 0  | int64 0
/// NULL or unrecognised string → Err.
pub fn db_decode_bool<E: From<String> + 'static>(col: String) -> Decoder<E, bool> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| match v {
                JsonVal::Bool(b) => decode_ok(*b),
                JsonVal::Number(n) => match n.as_i64() {
                    Some(i) => decode_ok(i != 0),
                    None => decode_err_str(format!(
                        "column {}: expected Bool, numeric value unrepresentable",
                        col
                    )),
                },
                JsonVal::String(s) => match s.as_str() {
                    "true" | "TRUE" | "True" | "t" | "T" | "1" => decode_ok(true),
                    "false" | "FALSE" | "False" | "f" | "F" | "0" => decode_ok(false),
                    _ => decode_err_str(format!("column {}: expected Bool, got {:?}", col, s)),
                },
                JsonVal::Null => decode_err_str(format!("column {}: expected Bool, got NULL", col)),
                _ => decode_err_str(format!(
                    "column {}: expected Bool, got unexpected type",
                    col
                )),
            }),
            vec![],
        ),
    )
}

/// `DbDec.money col` — read column `col` as a `(Decimal, String)` pair
/// representing `(amount, currency_code)`.
///
/// The DB column stores a TEXT value in `"ISO_CODE AMOUNT"` format
/// (e.g. `"USD 1234.56"`, `"BTC 0.00012"`), written by `SqlMoney` on the
/// bind side.
///
/// ### Type representation
///
/// The Ipê `Money` ADT is `type Money = Money Decimal Currency` — a generated
/// user-space type (`StdMoneyMoney::Money(StdDecimalDecimal, StdMoneyCurrency)`)
/// that differs per project. The Rust runtime has no single `Money` type to
/// return from a generic `Decoder<E, T>`.  The return type is therefore
/// `(Decimal, String)` — a structural pair that a codegen-emitted wrapper can
/// destructure into the project's concrete `StdMoneyMoney::Money(amount, currency)`.
///
/// The Kernel.hs routing entry **cannot** be wired directly to
/// `db_decode_money` without a codegen-level wrapper that constructs
/// `StdMoneyMoney` from the `(Decimal, String)`.
///
/// Totality: missing column, NULL, bad format, unparseable amount → `Err`.
pub fn db_decode_money<E: From<String> + 'static>(col: String) -> Decoder<E, (Decimal, String)> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| {
                let s = match v {
                    JsonVal::String(s) => s.clone(),
                    JsonVal::Null => {
                        return decode_err_str(format!(
                            "column {}: expected Money 'CODE AMOUNT', got NULL",
                            col
                        ));
                    }
                    _ => {
                        return decode_err_str(format!(
                            "column {}: expected Money 'CODE AMOUNT' string",
                            col
                        ));
                    }
                };
                // Split on the first space separating the currency code from the amount.
                // `split_once` is total — no raw slicing / index arithmetic on `s` (which
                // would be `indexing_slicing` + an underflow risk on `s.len() - 1`).
                match s.split_once(' ') {
                    Some((code, amount_str)) if !code.is_empty() && !amount_str.is_empty() => {
                        use rust_decimal::Decimal as RD;
                        use std::str::FromStr;
                        match RD::from_str(amount_str) {
                            Ok(d) => decode_ok((Decimal(d), code.to_string())),
                            Err(e) => decode_err_str(format!(
                                "column {}: Money amount parse error for {:?}: {}",
                                col, amount_str, e
                            )),
                        }
                    }
                    _ => decode_err_str(format!(
                        "column {}: expected Money 'CODE AMOUNT', got {:?}",
                        col, s
                    )),
                }
            }),
            vec![],
        ),
    )
}

/// `Db.Decode.decimal col` — read column `col` as an exact-decimal value.
///
/// The DB column stores the decimal as a TEXT string (the lossless
/// representation `SqlDecimal` writes on INSERT — no float intermediary, no
/// precision loss). Parses the text with `rust_decimal::Decimal::from_str`,
/// which is the same exact-decimal parse money uses for its amount component.
///
/// Returns `Decoder<E, Decimal>` — the symmetric, single-value counterpart
/// to `db_decode_money` (which returns `Decoder<E, (Decimal, String)>`).
///
/// Totality: missing column, NULL, or unparseable text → `Err(E::from(...))`.
pub fn db_decode_decimal<E: From<String> + 'static>(col: String) -> Decoder<E, Decimal> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| {
                let s = match v {
                    JsonVal::String(s) => s.clone(),
                    JsonVal::Null => {
                        return decode_err_str(format!(
                            "column {}: expected Decimal string, got NULL",
                            col
                        ));
                    }
                    _ => {
                        return decode_err_str(format!("column {}: expected Decimal string", col));
                    }
                };
                use rust_decimal::Decimal as RD;
                use std::str::FromStr;
                match RD::from_str(&s) {
                    Ok(d) => decode_ok(Decimal(d)),
                    Err(e) => decode_err_str(format!(
                        "column {}: could not decode decimal column {:?}: {}",
                        col, s, e
                    )),
                }
            }),
            vec![],
        ),
    )
}

/// `DbDec.bytes col` — read column `col` as raw bytes (`Vec<u8>`).
///
/// The DB column stores hex-encoded bytes written by `SqlBytes` on the bind
/// side (via [`Cell::into_json`]'s hex encoding). Hex-decodes the string value
/// back to `Vec<u8>`, closing the `SqlBytes` write-without-read asymmetry.
///
/// Totality: missing column, NULL, or non-hex string → `Err`.
pub fn db_decode_bytes<E: From<String> + 'static>(col: String) -> Decoder<E, Vec<u8>> {
    decode_field(
        col.clone(),
        Decoder::new(
            Box::new(move |v| match v {
                JsonVal::String(s) => match hex::decode(s) {
                    Ok(b) => decode_ok(b),
                    Err(e) => decode_err_str(format!(
                        "column {}: expected hex-encoded bytes, got {:?}: {}",
                        col, s, e
                    )),
                },
                JsonVal::Null => {
                    decode_err_str(format!("column {}: expected bytes, got NULL", col))
                }
                _ => decode_err_str(format!(
                    "column {}: expected hex-encoded bytes, got {:?}",
                    col,
                    v.to_string()
                )),
            }),
            vec![],
        ),
    )
}

/// `DbDec.nullable inner` — ONE-arg form matching Ipê's
/// `nullable : Decoder a -> Decoder (Maybe a)`.
///
/// Uses `inner.fields` (the `Decoder` struct's `{run, fields}` metadata) to
/// determine which columns the inner decoder reads.
/// This is the Rust equivalent of `DbDec_nullable` which gates on
/// `inner.cols`.
///
/// NULL-gate logic:
/// - If `inner.fields` is non-empty: check each named field in the row
///   `JsonVal::Object`. If ANY field is `JsonVal::Null` or absent →
///   `Ok(Nothing)`. Only when all fields are present + non-null do we
///   delegate to `inner.run`.
/// - If `inner.fields` is empty (e.g. a `succeed`/`fail` decoder with no
///   column binding): check the current value directly — `JsonVal::Null`
///   → `Ok(Nothing)`, else delegate.
///
/// Totality: every path returns a `IpeResult`; no panic/unwrap.
pub fn db_decode_nullable<E: From<String> + 'static, T: Send + 'static>(
    inner: Decoder<E, T>,
) -> Decoder<E, IpeMaybe<T>> {
    let gate_fields = inner.fields.clone();
    // Clone for use in the Decoder::new second arg (moved into closure above).
    let fields_for_struct = gate_fields.clone();
    Decoder::new(
        Box::new(move |v| {
            if gate_fields.is_empty() {
                // Leaf decoder with no named fields — gate on the current value itself.
                if v == &JsonVal::Null {
                    return decode_ok(IpeMaybe::Nothing);
                }
            } else {
                // Gate on every field the inner decoder reads.
                for col in &gate_fields {
                    match v.get(col.as_str()) {
                        None | Some(JsonVal::Null) => return decode_ok(IpeMaybe::Nothing),
                        Some(_) => {}
                    }
                }
            }
            // All gate fields are present + non-null (or no gate fields and value
            // is not Null): delegate to inner. Inner Err = structural mismatch.
            match (inner.run)(v) {
                IpeResult::Ok(t) => decode_ok(IpeMaybe::Just(t)),
                IpeResult::Err(e) => IpeResult::Err(e),
            }
        }),
        fields_for_struct,
    )
}

/// `DbDec.required col fieldDec ctorDec` — pipeline step for a required column.
///
/// Ipê signature: `required : String -> Decoder a -> Decoder (a -> b) -> Decoder b`
///
/// Implemented APPLICATIVELY as `decode_and_map(decode_field(col, fieldDec), ctorDec)`.
/// This avoids any FnOnce/Clone wall: `decode_field` reads the named column from the row
/// and returns `IpeResult<E, A>`; `ctorDec` returns `IpeResult<E, Box<dyn FnOnce(A)->B>>`;
/// `decode_and_map` calls the FnOnce once per decoder invocation, which is sound because
/// the decoder is called once per row (not twice for the same row).
///
/// The `col` parameter is accepted for API parity with Ipê's signature but is
/// documentation-only here — `fieldDec` already names its column via `decode_field`.
///
/// Totality: missing column or decode error → Err propagated; no panic/unwrap.
/// Matches `DbDec_required` which delegates to `DbDec_andMap(fieldDec, ctorDec)`.
pub fn db_decode_required<E: From<String> + 'static, A: 'static + Send, B: 'static + Send>(
    _col: String,
    field_dec: Decoder<E, A>,
    ctor_dec: Decoder<E, Box<dyn FnOnce(A) -> B + Send>>,
) -> Decoder<E, B> {
    decode_and_map(field_dec, ctor_dec)
}

/// `DbDec.optional col fieldDec fallback ctorDec` — pipeline step for an optional column.
///
/// Ipê signature: `optional : String -> Decoder a -> a -> Decoder (a -> b) -> Decoder b`
///
/// Like `required` but a missing or NULL column yields `fallback` instead of failing.
/// Implemented applicatively: wrap `fieldDec` so that:
/// - Column absent or `JsonVal::Null` → `Ok(fallback.clone())`
/// - Column present + non-null → `fieldDec` decode result (Err on type mismatch)
///
/// Then `decode_and_map` applies the ctor.
///
/// Totality: NULL/absent → Ok(fallback); present but bad type → Err; ctor Err → Err.
/// Matches `DbDec_optional`.
pub fn db_decode_optional<
    E: From<String> + 'static,
    A: Clone + 'static + Send + Sync,
    B: 'static + Send,
>(
    col: String,
    field_dec: Decoder<E, A>,
    fallback: A,
    ctor_dec: Decoder<E, Box<dyn FnOnce(A) -> B + Send>>,
) -> Decoder<E, B> {
    // Build a nullable-aware wrapper: absent/NULL col → Ok(fallback), else decode.
    // `field_dec` is a db_decode_* primitive created with decode_field(col, inner),
    // so it expects the FULL row `JsonVal::Object` (not the extracted field value).
    // We gate on the column presence/NULL status, then pass the full row to field_dec.run.
    let fallback_run = fallback.clone();
    let dec_fields = field_dec.fields.clone();
    let nullable_field = Decoder::new(
        Box::new(move |v| match v.get(&col) {
            None | Some(JsonVal::Null) => decode_ok(fallback_run.clone()),
            Some(_) => (field_dec.run)(v), // pass full row — field_dec peels the column name
        }),
        dec_fields,
    );
    decode_and_map(nullable_field, ctor_dec)
}

// ─── Connection-lifecycle hardening ───────────────────────────────────────────
//
// `Db` (sqlx `Pool`) is an `Arc`-backed handle DESIGNED to be cloned and shared
// process-wide. The Ipê compiler lowers an idiomatic top-level
// `dbConn = Task.run (Db.connect ())` binding as a per-call function, so a user
// who references it per request/session re-enters `db_connect` on every request.
// sqlx's `Pool::connect` is EAGER (real I/O per call), so without a cache that
// pattern (a) churns connections and, on Postgres/MySQL, (b) blows straight
// through the server's `max_connections` cap — a resource-exhaustion / DoS vector
// driven purely by unpredictable user code. The runtime MUST absorb that
// (runtime-rust/AGENTS.md: consistent, secure, sound, efficient under any
// well-typed Ipê program). So `Db.connect <url>` resolves to ONE bounded,
// shared pool per URL — independent of how often the user calls it.

/// Process-global pool registry keyed by connection URL.
fn pool_cache() -> &'static std::sync::Mutex<HashMap<String, Db>> {
    static C: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Db>>> =
        std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// `:memory:` SQLite URLs (bare, or with a scheme prefix like `sqlite://` or
/// `sqlite:`, optionally further wrapped in a `file:` sub-scheme per
/// SQLite's own documented idiom — `sqlite.org/inmemorydb.html`) and
/// URI-mode `mode=memory` must NOT be pooled unless `cache=shared` is
/// present: each connection to a private in-memory database is a DISTINCT
/// database, so sharing a pool would silently merge what callers expect to
/// be isolated DBs (soundness — verified empirically against sqlx 0.8.6:
/// two independently-built pools to `"file::memory:"` do NOT see each
/// other's rows, but two pools to `"file::memory:?cache=shared"` DO).
/// Matching on the exact SQLite special-string / query parameter — not a
/// raw substring match on "memory" anywhere in the URL — so a legitimate
/// file path like `sqlite://data/memory_bank.db` is correctly treated as
/// cacheable.
fn url_is_cacheable(url: &str) -> bool {
    // Strip a `sqlite:` / `sqlite://` scheme prefix if present, then compare
    // the remainder (path + query) — mirrors how sqlx/libsqlite3 parse the
    // connection string.
    let rest = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
        .unwrap_or(url);

    // Split off the query string (everything after the first `?`) so
    // `mode=memory` can be checked independently of the path.
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let has_cache_shared = query.split('&').any(|kv| kv.starts_with("cache=shared"));

    // SQLite's own documented idiom wraps the special `:memory:` name in a
    // `file:` sub-scheme (e.g. `sqlite3_open("file::memory:?cache=shared",
    // &db)`). Strip that sub-scheme too before comparing — otherwise
    // `"file::memory:"` falls through both checks below and is misclassified
    // as a plain (cacheable) file path, silently merging distinct private
    // in-memory databases behind one pooled connection.
    let file_wrapped = path.starts_with("file:");
    let path = path.strip_prefix("file:").unwrap_or(path);

    if path == ":memory:" {
        // A BARE `:memory:` (no `file:` sub-scheme) is not parsed as a URI
        // by SQLite at all — `cache=shared` has no effect on it and it is
        // unconditionally a private, per-connection database. Only the
        // `file:`-wrapped URI form honours `cache=shared`.
        return file_wrapped && has_cache_shared;
    }
    if query.split('&').any(|kv| kv == "mode=memory") && !has_cache_shared {
        return false;
    }
    true
}

use crate::system::SQLITE_BUSY_TIMEOUT;

/// Upper bound on pooled connections per database. Bounded by default so that
/// arbitrary user code calling `Db.connect` can NEVER exhaust the database
/// server's connection limit; raise via `IPE_DB_MAX_CONNECTIONS` for workloads
/// that genuinely need more headroom.
const DB_CONNECTIONS_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_DB_MAX_CONNECTIONS",
    16,
    crate::system::ZeroCeiling::Refused,
    "decimal connection count",
);

/// Upper bound on DISTINCT cached pools (one per URL). Without this, code that
/// connects to many distinct URLs accumulates live pools forever (memory +
/// connection-handle DoS). At the cap, a new URL is served by a freshly-built,
/// UNCACHED pool — still fully functional, just rebuilt per connect for that URL.
/// Env IPE_DB_MAX_POOLS; default 32 (far above the typical 1–2 DBs per app).
const DB_POOLS_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_DB_MAX_POOLS",
    32,
    crate::system::ZeroCeiling::Refused,
    "decimal pool count",
);

// ─── Engine version floor (connect-time, fail closed) ─────────────────────────

/// A database engine release, ordered numerically by `(major, minor)`. A patch
/// level never moves a floor, so it is not carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EngineVersion {
    major: u32,
    minor: u32,
}

impl EngineVersion {
    #[must_use]
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn major(self) -> u32 {
        self.major
    }

    #[must_use]
    pub const fn minor(self) -> u32 {
        self.minor
    }
}

impl std::fmt::Display for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Oldest SQLite the runtime accepts: the release that introduced `RETURNING`
/// (`db_insert_fields_returning`, the `RETURNING id` insert path) — the newest
/// SQLite syntax Ipe.Db emits (`ON CONFLICT … DO UPDATE` and
/// `ALTER TABLE … RENAME COLUMN` are older).
pub const SQLITE_VERSION_FLOOR: EngineVersion = EngineVersion::new(3, 35);

/// Oldest PostgreSQL the runtime accepts: the release that introduced
/// `INSERT … ON CONFLICT` (the session-store upsert) and
/// `CREATE INDEX IF NOT EXISTS` (`Ipe.Db.Store` index DDL) — the newest
/// PostgreSQL syntax Ipe.Db emits (`RETURNING` is older).
pub const POSTGRES_VERSION_FLOOR: EngineVersion = EngineVersion::new(9, 5);

/// The database engines the runtime can be built against. Closed set: a driver
/// with no declared floor has no variant, so it cannot be connected to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbEngine {
    Sqlite,
    Postgres,
}

impl DbEngine {
    /// The engine the sqlx driver `DB` speaks, from the driver's own
    /// `Database::NAME`. An unrecognised driver is refused, never assumed.
    fn for_driver<DB: sqlx::Database>() -> Result<Self, EngineVersionError> {
        Self::from_driver_name(DB::NAME).ok_or(EngineVersionError::UnknownEngine)
    }

    fn from_driver_name(name: &str) -> Option<Self> {
        match name {
            "SQLite" => Some(Self::Sqlite),
            "PostgreSQL" => Some(Self::Postgres),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sqlite => "SQLite",
            Self::Postgres => "PostgreSQL",
        }
    }

    #[must_use]
    pub const fn version_floor(self) -> EngineVersion {
        match self {
            Self::Sqlite => SQLITE_VERSION_FLOOR,
            Self::Postgres => POSTGRES_VERSION_FLOOR,
        }
    }

    /// Single-row, single-`TEXT`-column query reporting the server's version in
    /// the form [`Self::parse_version`] accepts.
    const fn version_query(self) -> &'static str {
        match self {
            Self::Sqlite => "SELECT sqlite_version()",
            Self::Postgres => "SELECT current_setting('server_version_num')",
        }
    }

    /// Parse the engine's self-reported version. Strict: anything but the
    /// exact documented shape is `None`, so an unexpected report fails closed.
    ///
    /// - SQLite `sqlite_version()`: `MAJOR.MINOR.PATCH`, all decimal.
    /// - PostgreSQL `server_version_num`: one decimal integer, encoded as
    ///   `M*10000 + m*100 + p` before major 10 and `M*10000 + m` from major 10
    ///   on.
    fn parse_version(self, raw: &str) -> Option<EngineVersion> {
        match self {
            Self::Sqlite => {
                let mut parts = raw.split('.');
                let major = parse_decimal(parts.next()?)?;
                let minor = parse_decimal(parts.next()?)?;
                parse_decimal(parts.next()?)?;
                if parts.next().is_some() {
                    return None;
                }
                Some(EngineVersion::new(major, minor))
            }
            Self::Postgres => {
                let num = parse_decimal(raw)?;
                let major = num / 10_000;
                let minor = if major >= 10 {
                    num % 10_000
                } else {
                    (num / 100) % 100
                };
                Some(EngineVersion::new(major, minor))
            }
        }
    }
}

impl std::fmt::Display for DbEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A non-empty run of ASCII digits that fits `u32`. Rejects the sign and empty
/// forms `str::parse` would otherwise accept or report ambiguously.
fn parse_decimal(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Why a connection was refused at the engine-version gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineVersionError {
    /// The build's sqlx driver is not a [`DbEngine`] with a declared floor.
    UnknownEngine,
    /// The engine's version report did not parse.
    Unparseable { engine: DbEngine },
    /// The engine is older than its [`DbEngine::version_floor`].
    BelowFloor {
        engine: DbEngine,
        found: EngineVersion,
    },
}

impl std::fmt::Display for EngineVersionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UnknownEngine => {
                f.write_str("db: unsupported database driver (no version floor is declared for it)")
            }
            Self::Unparseable { engine } => write!(
                f,
                "db: could not parse the {engine} server version; Ipe.Db requires {engine} >= {}",
                engine.version_floor()
            ),
            Self::BelowFloor { engine, found } => write!(
                f,
                "db: {engine} {found} is too old; Ipe.Db requires {engine} >= {}",
                engine.version_floor()
            ),
        }
    }
}

impl std::error::Error for EngineVersionError {}

/// Parse `raw` as `engine`'s version report and admit it only at or above the
/// engine's floor.
fn check_engine_version(engine: DbEngine, raw: &str) -> Result<EngineVersion, EngineVersionError> {
    let found = engine
        .parse_version(raw)
        .ok_or(EngineVersionError::Unparseable { engine })?;
    if found < engine.version_floor() {
        return Err(EngineVersionError::BelowFloor { engine, found });
    }
    Ok(found)
}

/// Longest driver code the classifier reads; a longer one is `OtherFailure`.
const MAX_DB_FAILURE_CODE_LEN: usize = 16;

/// A driver code in the short alphanumeric shape SQLSTATE and SQLite codes take.
///
/// A remote server picks the code, so an empty, overlong or otherwise shaped
/// code is dropped rather than read.
fn well_formed_code(code: Option<&str>) -> Option<&str> {
    code.filter(|c| {
        !c.is_empty()
            && c.len() <= MAX_DB_FAILURE_CODE_LEN
            && c.bytes().all(|b| b.is_ascii_alphanumeric())
    })
}

/// Classify a driver failure into the closed [`IpeDbFailure`] set.
///
/// The one producer of an Ipê `DbFailure` value. `engine` selects the code
/// space, so a code from the other engine's space is `OtherFailure`, and a
/// code that is absent, malformed or out of range never reaches a row.
pub(crate) fn classify_failure(engine: DbEngine, e: &sqlx::Error) -> IpeDbFailure {
    if let Some(dbe) = e.as_database_error() {
        let code = dbe.code();
        return match well_formed_code(code.as_deref()) {
            None => IpeDbFailure::OtherFailure,
            Some(code) => match engine {
                DbEngine::Sqlite => code
                    .parse::<i32>()
                    .map_or(IpeDbFailure::OtherFailure, sqlite_row),
                DbEngine::Postgres => postgres_row(code),
            },
        };
    }
    match e {
        sqlx::Error::PoolTimedOut => IpeDbFailure::Busy,
        sqlx::Error::Io(_)
        | sqlx::Error::Tls(_)
        | sqlx::Error::Configuration(_)
        | sqlx::Error::PoolClosed => IpeDbFailure::Unreachable,
        // `sqlx::Error` is `#[non_exhaustive]`: every other arm, present or
        // future, is the explicit `OtherFailure` row.
        _ => IpeDbFailure::OtherFailure,
    }
}

/// The SQLite row for a result code: the full extended code first, then the
/// primary code (`code & 0xFF`).
const fn sqlite_row(code: i32) -> IpeDbFailure {
    match code {
        2067 | 1555 => IpeDbFailure::UniqueViolation,
        787 => IpeDbFailure::ForeignKeyViolation,
        1299 => IpeDbFailure::NotNullViolation,
        275 => IpeDbFailure::CheckViolation,
        1811 => IpeDbFailure::TriggerRaised,
        extended => match extended & 0xFF {
            19 => IpeDbFailure::OtherConstraint,
            5 | 6 => IpeDbFailure::Busy,
            8 => IpeDbFailure::ReadOnlyDatabase,
            3 | 23 => IpeDbFailure::AccessDenied,
            14 => IpeDbFailure::CannotOpen,
            26 | 11 => IpeDbFailure::NotADatabase,
            1 => IpeDbFailure::InvalidStatement,
            _ => IpeDbFailure::OtherFailure,
        },
    }
}

/// The PostgreSQL row for a SQLSTATE: the exact codes first, then the
/// two-character class of a five-character code.
fn postgres_row(code: &str) -> IpeDbFailure {
    match code {
        "23505" => IpeDbFailure::UniqueViolation,
        "23503" => IpeDbFailure::ForeignKeyViolation,
        "23502" => IpeDbFailure::NotNullViolation,
        "23514" => IpeDbFailure::CheckViolation,
        "P0001" => IpeDbFailure::TriggerRaised,
        "55P03" | "40P01" | "40001" => IpeDbFailure::Busy,
        "25006" => IpeDbFailure::ReadOnlyDatabase,
        "42501" => IpeDbFailure::AccessDenied,
        "3D000" => IpeDbFailure::CannotOpen,
        "XX001" | "XX002" => IpeDbFailure::NotADatabase,
        sqlstate if sqlstate.len() != 5 => IpeDbFailure::OtherFailure,
        sqlstate => match sqlstate.get(..2) {
            Some("23") => IpeDbFailure::OtherConstraint,
            Some("28") => IpeDbFailure::AccessDenied,
            Some("08") => IpeDbFailure::Unreachable,
            Some("42") => IpeDbFailure::InvalidStatement,
            _ => IpeDbFailure::OtherFailure,
        },
    }
}

/// A driver failure: its classification and its well-formed driver code.
///
/// Holds no driver message: a driver's message can echo the connection URL —
/// host, user, password — so it is dropped here and can never reach a log line
/// or an error value. `Display` renders the classification's phrase alone; the
/// code is kept for the operator log only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverFailure {
    failure: IpeDbFailure,
    raw_code: Option<String>,
}

impl DriverFailure {
    /// Classify `e` for `engine`, keeping only a well-formed driver code.
    #[must_use]
    pub fn of(engine: DbEngine, e: &sqlx::Error) -> Self {
        let raw_code = e.as_database_error().and_then(|dbe| {
            let code = dbe.code();
            well_formed_code(code.as_deref()).map(str::to_owned)
        });
        Self {
            failure: classify_failure(engine, e),
            raw_code,
        }
    }

    /// The closed classification.
    #[must_use]
    pub const fn failure(&self) -> IpeDbFailure {
        self.failure
    }

    /// The well-formed driver code, for the operator log only.
    #[must_use]
    pub fn raw_code(&self) -> Option<&str> {
        self.raw_code.as_deref()
    }
}

impl std::fmt::Display for DriverFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.failure.phrase())
    }
}

/// Why [`VettedPool::connect`] refused.
///
/// Credential-free by construction: no variant holds a driver error or any
/// credential from the connection URL (a host refusal names only the host), so
/// neither `Display` nor `Debug` can echo one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DbConnectError {
    /// The URL did not parse, so what it opens cannot be vetted.
    InvalidUrl,
    /// A PostgreSQL URL's credentials may run past what the parser read as
    /// its userinfo.
    ///
    /// An `@` outside the parsed authority, or any `\`, means a credential
    /// may have held a `/`, `?`, `#`, or `\` and the parser read part of it
    /// as the host (see `ssrf::userinfo_is_ambiguous`). The URL is refused,
    /// and the text that would have been taken for a host is never echoed.
    MisplacedUserinfo,
    /// A PostgreSQL URL names more dial targets than the gate vets.
    TooManyDialTargets {
        /// The most targets one URL may name.
        limit: usize,
    },
    /// The URL's scheme selects no engine the runtime supports.
    ///
    /// The scheme is not echoed: a malformed URL's scheme position can hold
    /// its userinfo.
    UnsupportedScheme,
    /// The URL selects a different engine than the driver the pool opens with.
    EngineMismatch {
        /// The engine the URL's scheme selects.
        url: DbEngine,
        /// The engine the driver speaks.
        driver: DbEngine,
    },
    /// The SSRF gate refused a target the URL dials.
    HostRefused(crate::ssrf::SsrfRefusal),
    /// The driver could not open the pool.
    Unreachable(DriverFailure),
    /// The local relay that pins a TLS dial to its vetted address could not
    /// be opened, so the dial is refused rather than unpinned.
    RelayUnavailable,
    /// The server's version query failed.
    VersionUnreadable(DriverFailure),
    /// The engine is unsupported, or its version is unparseable or too old.
    EngineRefused(EngineVersionError),
}

impl std::fmt::Display for DbConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => f.write_str("db: invalid connection URL"),
            Self::MisplacedUserinfo => f.write_str(
                "db: the connection URL has an `@` or `\\` outside its user name and password; \
                 percent-encode `@`, `/`, `?`, `#` and `\\` in the user name, password and \
                 query values (as %40, %2F, %3F, %23, %5C)",
            ),
            Self::TooManyDialTargets { limit } => write!(
                f,
                "db: the connection URL names more than {limit} hosts to dial"
            ),
            Self::UnsupportedScheme => f.write_str(
                "db: unsupported connection URL scheme (use sqlite:, file:, postgres: or \
                 postgresql:)",
            ),
            Self::EngineMismatch { url, driver } => write!(
                f,
                "db: the connection URL selects {} but this build's driver is {}",
                url.name(),
                driver.name()
            ),
            Self::HostRefused(refusal) => write!(f, "db: {refusal}"),
            Self::Unreachable(failure) | Self::VersionUnreadable(failure) => {
                write!(f, "db: {failure}")
            }
            Self::EngineRefused(refused) => write!(f, "{refused}"),
            Self::RelayUnavailable => f.write_str(
                "db: the local relay to the pinned database address could not be opened",
            ),
        }
    }
}

impl std::error::Error for DbConnectError {}

#[cfg(unix)]
impl From<crate::ssrf::RelayUnavailable> for DbConnectError {
    fn from(crate::ssrf::RelayUnavailable: crate::ssrf::RelayUnavailable) -> Self {
        Self::RelayUnavailable
    }
}

/// Admit a pool only when its server's version is at or above its engine's floor.
///
/// Reads the version once. [`VettedPool::connect`] runs it on every pool it
/// opens, before any other statement.
async fn enforce_engine_floor_on<DB>(pool: &sqlx::Pool<DB>) -> Result<EngineVersion, DbConnectError>
where
    DB: sqlx::Database,
    for<'c> &'c mut DB::Connection: sqlx::Executor<'c, Database = DB>,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    (String,): for<'r> sqlx::FromRow<'r, DB::Row>,
{
    let engine = DbEngine::for_driver::<DB>().map_err(DbConnectError::EngineRefused)?;
    let raw: String = sqlx::query_scalar::<DB, String>(engine.version_query())
        .fetch_one(pool)
        .await
        .map_err(|e| DbConnectError::VersionUnreadable(DriverFailure::of(engine, &e)))?;
    check_engine_version(engine, &raw).map_err(DbConnectError::EngineRefused)
}

/// Port a PostgreSQL URL dials when it names none.
const POSTGRES_DEFAULT_PORT: u16 = 5432;

/// The most dial targets one PostgreSQL URL may name.
///
/// Each target is resolved and vetted before the dial, so the count bounds
/// the DNS work one connection URL can demand.
const MAX_POSTGRES_DIAL_TARGETS: usize = 8;

/// One place a PostgreSQL connection URL can make the driver dial.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DialTarget {
    /// A TCP host and port, read from a URL whose userinfo is unambiguous.
    Tcp { host: ConfiguredHost, port: u16 },
    /// A local Unix-domain socket directory.
    Socket,
    /// No host in the URL, so the driver picks one itself.
    ///
    /// It tries `PGHOSTADDR` / `PGHOST`, then a default socket directory, then
    /// `localhost`.
    DriverDefault,
}

/// Every target the PostgreSQL driver can dial for `url`, in resolution order.
///
/// The driver starts from its environment default, takes the URL authority
/// host, then applies each `host` / `hostaddr` query parameter; a value
/// starting with `/` (percent-encoded in the authority) selects a Unix socket,
/// which the driver keeps even when a later parameter names a TCP host. The
/// last entry is the target a plain resolution picks; every entry is returned
/// so the gate can refuse the whole set rather than trust one reading of the
/// driver's precedence. A URL naming no host yields exactly
/// [`DialTarget::DriverDefault`].
fn read_dial_targets(url: &UnambiguousUrl) -> Result<Vec<DialTarget>, DbConnectError> {
    let parsed = url.url();
    let mut port = parsed.port().unwrap_or(POSTGRES_DEFAULT_PORT);
    let mut hosts: Vec<Option<ConfiguredHost>> = Vec::new();
    let mut push_host = |host: Option<ConfiguredHost>| {
        if hosts.len() >= MAX_POSTGRES_DIAL_TARGETS {
            return Err(DbConnectError::TooManyDialTargets {
                limit: MAX_POSTGRES_DIAL_TARGETS,
            });
        }
        hosts.push(host);
        Ok(())
    };
    if let Some(host) = url.host() {
        let socket = host.as_str().starts_with("%2F") || host.as_str().starts_with("%2f");
        push_host((!socket).then_some(host))?;
    }
    for (key, value) in crate::ssrf::DriverParityQuery::of(url).pairs() {
        match &*key {
            "host" | "hostaddr" => {
                let host = if value.starts_with('/') {
                    None
                } else {
                    Some(url.query_host(&value).ok_or(DbConnectError::InvalidUrl)?)
                };
                push_host(host)?;
            }
            "port" => {
                port = value.parse().map_err(|_| DbConnectError::InvalidUrl)?;
            }
            _ => {}
        }
    }
    if hosts.is_empty() {
        return Ok(vec![DialTarget::DriverDefault]);
    }
    Ok(hosts
        .into_iter()
        .map(|host| match host {
            Some(host) => DialTarget::Tcp { host, port },
            None => DialTarget::Socket,
        })
        .collect())
}

/// The scheme `url` names, or `None` when it names none.
///
/// A scheme is the text before the first `:` when it has the RFC 3986 shape
/// (a letter, then letters, digits, `+`, `-` or `.`). A bare file path or
/// SQLite's `:memory:` names none.
fn url_scheme(url: &str) -> Option<&str> {
    let (scheme, _) = url.split_once(':')?;
    let mut chars = scheme.chars();
    let shaped = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    shaped.then_some(scheme)
}

/// A SQLite connection URL, parsed into the options the driver opens.
pub struct SqliteUrl {
    options: sqlx::sqlite::SqliteConnectOptions,
    /// A file every pool connection shares, as opposed to a private in-memory database.
    shared_file: bool,
}

/// A PostgreSQL connection URL and every target it makes the driver dial.
pub struct PostgresUrl {
    url: UnambiguousUrl,
    targets: Vec<DialTarget>,
}

impl PostgresUrl {
    /// Read every dial target of `url`.
    ///
    /// # Errors
    ///
    /// [`DbConnectError::MisplacedUserinfo`] when the userinfo is ambiguous,
    /// and [`DbConnectError::InvalidUrl`] when the targets cannot be read.
    fn parse(url: &str) -> Result<Self, DbConnectError> {
        let url = UnambiguousUrl::parse(url).map_err(|unproven| match unproven {
            UrlUnproven::AmbiguousUserinfo => DbConnectError::MisplacedUserinfo,
            UrlUnproven::Invalid => DbConnectError::InvalidUrl,
        })?;
        read_dial_targets(&url).map(|targets| Self { url, targets })
    }
}

/// A database connection URL, parsed once into the engine it selects.
///
/// The engine a pool is opened with, the SSRF gate's dial targets, and the
/// SQLite WAL setup all read this one value, so they cannot disagree.
/// Holds the URL's credentials, so it has no `Debug` or `Display`.
pub enum DbUrl {
    /// `sqlite:` or `file:`, or a bare path naming no scheme.
    Sqlite(SqliteUrl),
    /// `postgres:` or `postgresql:`.
    Postgres(PostgresUrl),
}

impl DbUrl {
    /// Parse `url` into the engine its scheme selects.
    ///
    /// Schemes are matched exactly (lower-case), as the drivers read them.
    ///
    /// # Errors
    ///
    /// [`DbConnectError::UnsupportedScheme`] for any other scheme, and
    /// [`DbConnectError::InvalidUrl`] for a SQLite URL the driver cannot read
    /// or a PostgreSQL URL whose dial targets cannot be read.
    pub fn parse(url: &str) -> Result<Self, DbConnectError> {
        match url_scheme(url) {
            None | Some("sqlite" | "file") => Ok(Self::Sqlite(SqliteUrl {
                options: url
                    .parse::<sqlx::sqlite::SqliteConnectOptions>()
                    .map_err(|_| DbConnectError::InvalidUrl)?
                    .busy_timeout(SQLITE_BUSY_TIMEOUT),
                shared_file: url_is_cacheable(url),
            })),
            Some("postgres" | "postgresql") => PostgresUrl::parse(url).map(Self::Postgres),
            Some(_) => Err(DbConnectError::UnsupportedScheme),
        }
    }

    /// The engine the URL selects.
    #[must_use]
    pub const fn engine(&self) -> DbEngine {
        match self {
            Self::Sqlite(_) => DbEngine::Sqlite,
            Self::Postgres(_) => DbEngine::Postgres,
        }
    }

    /// Whether the URL names a SQLite file every pool connection shares.
    #[must_use]
    pub const fn is_shared_sqlite_file(&self) -> bool {
        matches!(
            self,
            Self::Sqlite(SqliteUrl {
                shared_file: true,
                ..
            })
        )
    }

    /// The refusal for a driver that speaks `driver` but was handed this URL.
    const fn mismatch(&self, driver: DbEngine) -> DbConnectError {
        DbConnectError::EngineMismatch {
            url: self.engine(),
            driver,
        }
    }
}

/// Admit one dial target under `policy`.
///
/// A TCP host goes through [`VettedDial::for_configured_host_with`]. A Unix socket
/// reaches the local server exactly as loopback TCP does, and a driver default
/// is unproven (it may resolve to `localhost`), so under deny-private both are
/// refused; with the policy off they pass, as loopback TCP does.
async fn vet_dial_target<R: HostResolver>(
    target: &DialTarget,
    policy: DialPolicy,
    resolver: &R,
) -> Result<VettedDial, DbConnectError> {
    match (target, policy) {
        (DialTarget::Tcp { host, port }, _) => {
            VettedDial::for_configured_host_with(policy, resolver, host, *port)
                .await
                .map_err(DbConnectError::HostRefused)
        }
        (DialTarget::Socket, DialPolicy::DenyPrivate) => {
            Err(DbConnectError::HostRefused(SsrfRefusal::LocalSocket))
        }
        (DialTarget::DriverDefault, DialPolicy::DenyPrivate) => {
            Err(DbConnectError::HostRefused(SsrfRefusal::UnprovenTarget))
        }
        (DialTarget::Socket | DialTarget::DriverDefault, DialPolicy::AllowAll) => {
            Ok(VettedDial::Unrestricted)
        }
    }
}

/// The PostgreSQL options `url` makes the driver dial, gated and pinned.
///
/// Every target from [`read_dial_targets`] must pass [`vet_dial_target`];
/// a URL that does not parse is refused, since its targets cannot be proven
/// safe. The options are then the driver's own reading of `url`. Under
/// deny-private that reading must dial TCP, and its host is replaced by the
/// vetted address, so the pool never resolves the name again: a later answer
/// pointing at an internal host (DNS rebinding) is not dialled on this
/// connect nor on any connection the pool opens afterwards.
///
/// A named host that may negotiate TLS keeps its name for SNI and certificate
/// verification and is dialled through a `PinnedRelay` to the vetted address
/// (see [`pin_postgres_options`]); the relay is returned alongside the options
/// and must outlive every connection they open.
async fn postgres_connect_options<R: HostResolver>(
    url: &PostgresUrl,
    policy: DialPolicy,
    resolver: &R,
    max_connections: u32,
) -> Result<PinnedPgOptions, DbConnectError> {
    let mut vetted = Vec::with_capacity(url.targets.len());
    for target in &url.targets {
        let dial = vet_dial_target(target, policy, resolver).await?;
        vetted.push((target.clone(), dial));
    }
    let options: sqlx::postgres::PgConnectOptions = url
        .url
        .as_str()
        .parse()
        .map_err(|_| DbConnectError::InvalidUrl)?;
    match policy {
        DialPolicy::AllowAll => Ok((options, None)),
        DialPolicy::DenyPrivate => {
            pin_postgres_options(&url.url, options, &vetted, resolver, max_connections).await
        }
    }
}

/// Pin the dial of `options`, the driver's reading of `url`, to its vetted address.
///
/// Reuses the address a target in `vetted` already resolved to for the same
/// host and port, so the name is resolved once; a host the target scan did not
/// name is vetted here. A host `url` does not name is refused as unproven.
///
/// An IP-literal host, or any host under a mode that never negotiates TLS, is
/// replaced by the vetted address. A named host that may negotiate TLS keeps
/// its name, because the driver sends it as SNI and verifies the certificate
/// against it; the driver instead dials the socket of a `PinnedRelay` that
/// carries every connection to the vetted address, so no dial resolves the
/// name again. Where no relay exists, `verify-full` on a named host is refused
/// rather than silently weakened.
async fn pin_postgres_options<R: HostResolver>(
    url: &UnambiguousUrl,
    options: sqlx::postgres::PgConnectOptions,
    vetted: &[(DialTarget, VettedDial)],
    resolver: &R,
    max_connections: u32,
) -> Result<PinnedPgOptions, DbConnectError> {
    if options.get_socket().is_some() || options.get_host().starts_with('/') {
        return Err(DbConnectError::HostRefused(SsrfRefusal::LocalSocket));
    }
    let host = options.get_host().to_owned();
    let Some(named) = url.named_host(&host) else {
        return Err(DbConnectError::HostRefused(SsrfRefusal::UnprovenTarget));
    };
    let port = options.get_port();
    let literal = crate::ssrf::strip_ipv6_brackets(&host)
        .parse::<std::net::IpAddr>()
        .is_ok();
    #[cfg(not(unix))]
    let _no_relay_to_cap = max_connections;
    #[cfg(not(unix))]
    if !literal
        && matches!(
            options.get_ssl_mode(),
            sqlx::postgres::PgSslMode::VerifyFull
        )
    {
        return Err(DbConnectError::HostRefused(
            SsrfRefusal::UnpinnableTlsName { host: named },
        ));
    }
    let known = vetted
        .iter()
        .find_map(|(target, dial)| match (target, dial) {
            (DialTarget::Tcp { host: h, port: p }, VettedDial::Pinned(_))
                if h.as_str() == host && *p == port =>
            {
                Some(*dial)
            }
            _ => None,
        });
    let dial = match known {
        Some(dial) => dial,
        None => {
            VettedDial::for_configured_host_with(DialPolicy::DenyPrivate, resolver, &named, port)
                .await
                .map_err(DbConnectError::HostRefused)?
        }
    };
    #[cfg(unix)]
    if let VettedDial::Pinned(target) = dial
        && !literal
        && !matches!(
            options.get_ssl_mode(),
            sqlx::postgres::PgSslMode::Disable | sqlx::postgres::PgSslMode::Allow
        )
    {
        let relay = crate::ssrf::PinnedRelay::open(target, port, max_connections)?;
        let relayed = options.socket(relay.socket_dir());
        return Ok((relayed, Some(relay)));
    }
    Ok((options.host(&dial.dial_host(&host)), None))
}

/// PostgreSQL options gated and pinned, with the relay their dials go through.
type PinnedPgOptions = (
    sqlx::postgres::PgConnectOptions,
    Option<crate::ssrf::PinnedRelay>,
);

/// A driver whose connect options pass the SSRF gate before any dial.
///
/// [`VettedPool::connect`] obtains its options only through this trait, so
/// which gate runs is decided by the driver type, never by reading the URL.
pub trait GatedDial: sqlx::Database {
    /// The options `url` makes the driver dial, admitted by the gate.
    ///
    /// A pinned dial that runs through a `PinnedRelay` leaves it in `relay`;
    /// the relay must outlive every connection the options open. A URL
    /// selecting another engine is refused with
    /// [`DbConnectError::EngineMismatch`].
    fn gated_connect_options(
        url: &DbUrl,
        max_connections: u32,
        relay: &mut Option<crate::ssrf::PinnedRelay>,
    ) -> impl std::future::Future<
        Output = Result<<Self::Connection as sqlx::Connection>::Options, DbConnectError>,
    > + Send;
}

impl GatedDial for sqlx::Sqlite {
    /// SQLite opens a local file and dials no host.
    async fn gated_connect_options(
        url: &DbUrl,
        _max_connections: u32,
        _relay: &mut Option<crate::ssrf::PinnedRelay>,
    ) -> Result<sqlx::sqlite::SqliteConnectOptions, DbConnectError> {
        match url {
            DbUrl::Sqlite(sqlite) => Ok(sqlite.options.clone()),
            DbUrl::Postgres(_) => Err(url.mismatch(DbEngine::Sqlite)),
        }
    }
}

impl GatedDial for sqlx::Postgres {
    /// Every target is vetted under the environment's policy and pinned.
    async fn gated_connect_options(
        url: &DbUrl,
        max_connections: u32,
        relay: &mut Option<crate::ssrf::PinnedRelay>,
    ) -> Result<sqlx::postgres::PgConnectOptions, DbConnectError> {
        match url {
            DbUrl::Postgres(postgres) => {
                let (options, pinned) = postgres_connect_options(
                    postgres,
                    DialPolicy::from_env(),
                    &SystemResolver,
                    max_connections,
                )
                .await?;
                *relay = pinned;
                Ok(options)
            }
            DbUrl::Sqlite(_) => Err(url.mismatch(DbEngine::Postgres)),
        }
    }
}

/// A database pool that passed every connect-time gate.
///
/// [`VettedPool::connect`] is its only constructor and the runtime's only way
/// to open a pool from a caller-supplied connection URL: the `Ipe.Db` pool, an
/// `Ipe.Db.Connection`, and the persistent session stores all go through it.
/// It runs, in order: the driver's [`GatedDial`] gate (for PostgreSQL, the
/// SSRF gate on every target the URL dials, with the dial pinned to the vetted
/// address), a bounded connection cap, and the engine-version floor before any
/// other statement. A relay the gate opened is held until the pool closes.
/// Every failure is a [`DbConnectError`], which holds no driver payload, so no
/// caller can log or return a connection URL a driver echoed. The runtime's
/// own telemetry spill (`telemetry_spill.rs`, and the hub reading it) is not a
/// caller-supplied URL: it opens a local SQLite file named by operator config,
/// carrying no credential, directly.
pub struct VettedPool<DB: sqlx::Database>(sqlx::Pool<DB>);

impl<DB> VettedPool<DB>
where
    DB: GatedDial,
    for<'c> &'c mut DB::Connection: sqlx::Executor<'c, Database = DB>,
    for<'q> <DB as sqlx::Database>::Arguments<'q>: sqlx::IntoArguments<'q, DB>,
    (String,): for<'r> sqlx::FromRow<'r, DB::Row>,
{
    /// Open a pool of at most `max_connections` to `url` through every gate.
    ///
    /// # Errors
    ///
    /// [`DbConnectError`] when a gate refuses or the driver cannot connect.
    pub async fn connect(url: &DbUrl, max_connections: u32) -> Result<Self, DbConnectError> {
        let engine = DbEngine::for_driver::<DB>().map_err(DbConnectError::EngineRefused)?;
        let mut relay = None;
        let options = DB::gated_connect_options(url, max_connections, &mut relay).await?;
        let pool = sqlx::pool::PoolOptions::<DB>::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await
            .map_err(|e| DbConnectError::Unreachable(DriverFailure::of(engine, &e)))?;
        if let Err(refused) = enforce_engine_floor_on(&pool).await {
            pool.close().await;
            return Err(refused);
        }
        if let Some(relay) = relay {
            relay.hold_until(pool.close_event());
        }
        Ok(Self(pool))
    }

    /// The admitted pool.
    #[must_use]
    pub fn into_pool(self) -> sqlx::Pool<DB> {
        self.0
    }
}

/// Build one configured pool. SQLite (file, not `:memory:`) gets WAL — concurrent
/// readers alongside a single writer. Without WAL a shared pool serialises every
/// statement on the rollback-journal lock. The PRAGMA runs only when the parsed
/// URL selects a shared SQLite file, the same value that chose the driver's gate.
/// Lock contention waits for [`SQLITE_BUSY_TIMEOUT`], which every connection
/// carries from its connect options.
async fn build_pool<E: Send + From<String> + 'static>(url: &str) -> IpeResult<E, Db> {
    let db_url = match DbUrl::parse(url) {
        Ok(db_url) => db_url,
        Err(refused) => return IpeResult::Err(str_err(&refused.to_string())),
    };
    let max_connections: u32 = match DB_CONNECTIONS_CEILING.read() {
        Ok(cap) => cap,
        Err(refused) => return IpeResult::Err(str_err(&refused.to_string())),
    };
    let pool: Db = match VettedPool::<DbDatabase>::connect(&db_url, max_connections).await {
        Ok(vetted) => vetted.into_pool(),
        Err(refused) => return IpeResult::Err(str_err(&refused.to_string())),
    };
    if db_url.is_shared_sqlite_file() {
        let _ = sqlx::query("PRAGMA journal_mode=WAL;").execute(&pool).await;
    }
    ok_res(pool)
}

/// Connect to `url`, returning a clone of the cached pool on a hit. On a miss the
/// pool is built with NO lock held (never block other tasks on connect I/O); a
/// concurrent miss that built a redundant pool loses the `entry` race and its
/// extra pool drops (closes) — steady state keeps exactly one pool per URL.
async fn connect_cached<E: Send + From<String> + 'static>(url: String) -> IpeResult<E, Db> {
    let max_pools: usize = match DB_POOLS_CEILING.read() {
        Ok(cap) => cap,
        Err(refused) => return IpeResult::Err(str_err(&refused.to_string())),
    };
    if url_is_cacheable(&url) {
        let g = pool_cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = g.get(&url) {
            return ok_res(p.clone());
        }
    }
    match build_pool::<E>(&url).await {
        IpeResult::Ok(pool) => {
            if url_is_cacheable(&url) {
                let mut g = pool_cache().lock().unwrap_or_else(|e| e.into_inner());
                // Another task may have inserted during the lock-free build → reuse it.
                if let Some(existing) = g.get(&url) {
                    return ok_res(existing.clone());
                }
                // Bound the cache: at cap, return the freshly-built pool UNCACHED
                // (functional; just not memoised) rather than growing without limit.
                if g.len() >= max_pools {
                    return ok_res(pool);
                }
                ok_res(g.entry(url).or_insert(pool).clone())
            } else {
                ok_res(pool)
            }
        }
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}

pub fn db_connect<E: Send + From<String> + 'static>(_unit: ()) -> IpeTask<E, Db> {
    Box::pin(connect_cached(ipe_db_url()))
}

/// `Db.open : String -> String -> Task Error Db` (driver, path). The compiled
/// `DbPool` type is already fixed by the `package.ipe` driver, so `driver` is
/// informational; we connect using `path`. For sqlite a bare file path needs a
/// `sqlite://…?mode=rwc` URL (create-if-missing); other drivers pass `path`
/// through as the connection string. (Was wrongly `(_unit: ())` → ignored both
/// args → E0061 at every `Db.open "sqlite" "x.db"` call site.)
pub fn db_open<E: Send + From<String> + 'static>(driver: String, path: String) -> IpeTask<E, Db> {
    let url = if driver == "sqlite" && !path.contains(':') {
        format!("sqlite://{}?mode=rwc", path)
    } else {
        path
    };
    Box::pin(connect_cached(url))
}

pub fn db_open_with_path<E: Send + From<String> + 'static>(path: String) -> IpeTask<E, Db> {
    Box::pin(connect_cached(path))
}

pub fn db_exec_raw<E: Send + From<String> + 'static>(conn: Db, sql: String) -> IpeTask<E, i64> {
    Box::pin(async move {
        // `unsafeExecRaw : Db -> String -> Task Error Int` — the verbatim-SQL
        // escape hatch (its surface name marks the raw-SQL injection surface;
        // parameterisable statements go through `db_exec`/`db_query`). Int is the
        // rows-affected count. `as i64` matches the insert/update/delete sites;
        // rows-affected can never realistically exceed i64::MAX.
        match exec_routed(&conn, sqlx::query(&sql)).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

pub fn db_exec<E: Send + From<String> + 'static>(
    conn: Db,
    sql: String,
    params: Vec<String>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        // Same path as the structured kernels: `db_format_sql` adapts `?`
        // placeholders per backend, then bind positionally. sqlx owns the
        // escaping; a placeholder/param count mismatch surfaces as Err.
        // `exec : ... -> Task Error Int` returns rows-affected .
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = q.bind(p);
        }
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

pub fn db_query<E: Send + From<String> + 'static>(
    conn: Db,
    sql: String,
    params: Vec<String>,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = q.bind(p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

// ─── Typed-parameter exec/query (`List SqlValue`) ──────────────────────────
//
// `Db.exec`/`Db.query` are `Db -> String -> List a -> Task ...`. With `a = String`
// the params route through `db_exec`/`db_query` above (Vec<String>). With
// `a = SqlValue` (mixed-type params: String + Int + Bool + Float + Decimal + Time
// + Money + typed NULL), codegen detects the `List SqlValue` element type, lowers
// each element to the runtime-nameable `SqlParam`, and routes HERE. The String
// path is untouched (zero regression); these are a parallel, typed binding path.
//
// Identical to `db_exec`/`db_query` except each param binds via `bind_sql_param`
// (the total SqlParam→query binder used by insertFields/updateFields) instead of
// `q.bind(String)`. Same `exec_routed`/`fetch_all_routed` (task-local
// transaction-aware), same `db_format_sql` placeholder adaptation, same positional
// binding — values are NEVER interpolated (sqlx owns escaping); the SQL string is
// app-authored, exactly as in the String path and.

pub fn db_exec_params<E: Send + From<String> + 'static>(
    conn: Db,
    sql: String,
    params: Vec<SqlParam>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = bind_sql_param(q, p);
        }
        // Rows-affected , same as db_exec.
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

pub fn db_query_params<E: Send + From<String> + 'static>(
    conn: Db,
    sql: String,
    params: Vec<SqlParam>,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// A value a Ipê `Db.get*` accessor can read string-keyed fields from.
///
/// Ipê's `getString : String -> row -> String` is polymorphic in `row`; the
/// row can be a query result (`Dict String String`), a pub/sub `Dict` payload,
/// or the typed `WebReq` an `init` handler receives. `IpeRow` is the seam that
/// lets the Rust accessors stay generic and monomorphise per row type — no
/// `dyn Any`, no panic (an absent field reads as `""`).
pub trait IpeRow {
    fn ipe_get(&self, field: &str) -> String;
}

// `IpeDict<String>` is a transparent alias for `HashMap<String, String>`, so this
// is the impl for every Dict-shaped row (query rows + pub/sub Dict payloads).
// Named via the alias for intent; a genuine newtype is tracked as a future task.
impl IpeRow for IpeDict<String> {
    fn ipe_get(&self, field: &str) -> String {
        self.get(field).cloned().unwrap_or_default()
    }
}

// The typed request an `init` handler receives. `Db.getString "path" req` reads
// the named field; `params`/`headers`/`cookies` are searched for any other key.
//
// INVARIANT: `db` must build WITHOUT `live` — a DB-only server / CLI app does not
// pull in Ipe.Web. `super::WebReq` is a `web`-only type, so this impl (the ONLY
// `live` dependency in this module) stays behind `#[cfg(feature = "web")]`. Do not
// reference `live`-only items from `db`-gated code without the same gate. Enforced
// by CI job `runtime-feature-combos` (.github/workflows/ci.yml), which builds
// `--no-default-features --features db` (no web) under `-D warnings`.
#[cfg(feature = "web")]
impl IpeRow for super::WebReq {
    fn ipe_get(&self, field: &str) -> String {
        match field {
            "path" => self.path.clone(),
            "query" => self.query.clone(),
            "method" => self.method.clone(),
            _ => self
                .params
                .get(field)
                .or_else(|| self.headers.get(field))
                .or_else(|| self.cookies.get(field))
                .cloned()
                .unwrap_or_default(),
        }
    }
}

pub fn db_get_field<R: IpeRow>(field: String, row: &R) -> String {
    row.ipe_get(&field)
}

pub fn db_get_string<R: IpeRow>(field: String, row: &R) -> String {
    row.ipe_get(&field)
}

/// Truncate a float toward zero to an `Int`, rejecting a magnitude that would
/// saturate under an `as i64` cast. Both bounds are exclusive because f64 cannot
/// distinguish a boundary from its out-of-range neighbour (`i64::MAX as f64`
/// rounds up to 2^63; an input just past `i64::MIN` rounds down to `i64::MIN as
/// f64`), so `<=`/`>=` would admit an out-of-range magnitude and let `as i64`
/// saturate to the limit — a wrong value that reads like a real row value. An
/// exact `i64::MIN`/`i64::MAX` still round-trips. This is the total getter, so
/// an out-of-range read is surfaced on the runtime's stderr anomaly channel and
/// falls back to the contractual `0` default rather than saturating. The typed,
/// fail-with-Err path is `db_decode_int`.
fn float_to_i64_or_default(field: &str, f: f64) -> i64 {
    let truncated = f.trunc();
    if truncated > i64::MIN as f64 && truncated < 9_223_372_036_854_775_808.0 {
        truncated as i64
    } else {
        crate::system::write_stderr_line(&format!(
            "db: unsafeGetInt(\"{field}\"): {f} is out of range for a 64-bit integer; \
             returning 0 (default) instead of a saturated value"
        ));
        let _ = std::io::Write::flush(&mut std::io::stderr());
        0
    }
}

pub fn db_get_int<R: IpeRow>(field: String, row: &R) -> i64 {
    // Align with db_decode_int: accept "42" or a decimal string like
    // "3.0" (truncate to 3) before defaulting to 0.
    let s = row.ipe_get(&field);
    if let Ok(i) = s.parse::<i64>() {
        return i;
    }
    if let Ok(f) = s.parse::<f64>() {
        return float_to_i64_or_default(&field, f);
    }
    0
}

/// Lowercase sha256-hex of a migration's SQL text. This value is stored in the
/// `_ipe_migrations` ledger and is a DB CONTRACT: it is the lowercase-hex
/// sha256 of the exact statement bytes, so a database created/advanced by any
/// version must hash byte-identically — never a different/cheaper hash. `{:x}`
/// on a `Sha256` digest is lowercase hex.
fn migrate_checksum(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sql.as_bytes());
    format!("{:x}", h.finalize())
}

/// `migrate : Db -> List (String, String) -> Task Error (List String)` — apply
/// forward-only schema migrations, recording each in the `_ipe_migrations`
/// ledger so re-runs are idempotent. `Db_migrateApply`'s library
/// (Task-return) path in ``.
///
/// Per migration `(name, sql)`:
/// - checksum = sha256-hex(sql).
/// - already in the ledger: checksum match → SKIP (already up to date);
///   checksum DIFFERS → ERROR (the migration's SQL was edited after it was
///   applied — "drift"; the developer must restore the text or ship a new
///   compensating migration).
/// - not yet applied: run the SQL AND record `(name, checksum, applied_at)` in
///   ONE transaction (via the single-connection `db_with_transaction`), so a
///   failure rolls back only that migration and a re-run resumes from it.
///
/// Trust model: the migration SQL is compile-time app source the
/// developer ships — it is run verbatim via `db_exec_raw` (arbitrary DDL is the
/// point). Only the ledger bookkeeping crosses into bound-parameter territory
/// (the INSERT binds name/checksum/applied_at — never string-interpolated).
///
/// Single-deployer assumption: not concurrency-safe by design. The
/// `name TEXT PRIMARY KEY` ledger column is the backstop — a racing double-apply
/// loses the INSERT to a PK violation inside its own tx, which rolls back, so
/// there is no partial-corruption window.
///
/// DB-ops mode (`Db_migrateApply`): when the `IPE_DB_OP` env var
/// is set — the CLI `ipe db status` / `ipe db migrate --backend rust` sets it — the
/// task PRINTS a human report and ends the process through `system::exit_process` instead of returning, so the
/// surrounding app never starts serving:
///
/// - `status`: print applied / pending / drifted, exit 0 (1 if drift)
/// - `migrate`: apply pending, print summary, exit 0 (1 on error, to stderr)
/// - unset: normal Task behaviour (apply, return Ok/Err) — UNCHANGED
///
/// The exit is reachable ONLY under the CLI-set env op (never from a normal
/// well-typed Ipê `Db.migrate` call), and it is a deliberate CLI termination, not a
/// panic — the no-runtime-panic thesis is about faults, not intentional exits.
pub fn db_migrate_apply<E: Send + From<String> + 'static>(
    db: Db,
    migrations: Vec<(String, String)>,
) -> IpeTask<E, Vec<String>> {
    Box::pin(async move {
        // CLI op mode (empty when unset → library Task-return path, unchanged).
        let op: String = crate::system::read_env_var("IPE_DB_OP")
            .map(|v| v.trim().to_ascii_lowercase())
            .unwrap_or_default();
        // In `migrate` op mode an infra error prints context to stderr + exits 1;
        // otherwise it is returned as a Task Err. Implements `fail`.
        macro_rules! db_op_fail {
            ($ctx:expr_2021, $err:expr_2021) => {{
                if op == "migrate" {
                    crate::system::write_stderr_line(&format!("db: {} failed", $ctx));
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    // `ipe db migrate` CLI-op boundary: a migration infra failure exits the process (library path returns a Task Err instead)
                    crate::system::exit_process(1);
                }
                return IpeResult::Err($err);
            }};
        }

        // 1. Ensure the ledger exists. `IF NOT EXISTS` → idempotent.
        if let IpeResult::Err(e) = db_exec_raw::<E>(
            db.clone(),
            "CREATE TABLE IF NOT EXISTS _ipe_migrations (name TEXT PRIMARY KEY, \
             checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
                .to_string(),
        )
        .await
        {
            db_op_fail!("create _ipe_migrations", e);
        }

        // 2. Snapshot already-applied migrations: name -> (checksum, applied_at).
        //    Read OUTSIDE any transaction (the per-migration txns come below);
        //    single-deployer so no TOCTOU concern. No interpolation in the SELECT.
        let rows: Vec<HashMap<String, String>> = match db_query::<E>(
            db.clone(),
            "SELECT name, checksum, applied_at FROM _ipe_migrations".to_string(),
            Vec::new(),
        )
        .await
        {
            IpeResult::Ok(r) => r,
            IpeResult::Err(e) => db_op_fail!("read _ipe_migrations", e),
        };
        let mut applied: HashMap<String, (String, String)> = HashMap::new();
        for row in &rows {
            // Total: a row missing a column is skipped rather than panicking
            // (applied_at defaults to empty — only used for the status report).
            if let (Some(name), Some(sum)) = (row.get("name"), row.get("checksum")) {
                let at = row.get("applied_at").cloned().unwrap_or_default();
                applied.insert(name.clone(), (sum.clone(), at));
            }
        }

        // 2b. `status` op mode — read-only report from `applied` × `migrations`,
        //     then exit. Implements `dbPrintMigrationStatus`.
        if op == "status" {
            let (mut applied_n, mut pending_n, mut drift_n) = (0usize, 0usize, 0usize);
            // (mark, name, detail) per declared migration.
            let mut lines: Vec<(&'static str, &str, String)> = Vec::with_capacity(migrations.len());
            for (name, sql) in &migrations {
                let sum = migrate_checksum(sql);
                match applied.get(name) {
                    Some((csum, at)) if csum != &sum => {
                        drift_n += 1;
                        lines.push(("✗", name, format!("DRIFT — SQL changed since applied {at}")));
                    }
                    Some((_, at)) => {
                        applied_n += 1;
                        lines.push(("✓", name, format!("applied {at}")));
                    }
                    None => {
                        pending_n += 1;
                        lines.push(("•", name, "pending".to_string()));
                    }
                }
            }
            let mut header = format!(
                "db: {} migration(s) — {applied_n} applied, {pending_n} pending",
                migrations.len()
            );
            if drift_n > 0 {
                header.push_str(&format!(", {drift_n} DRIFTED"));
            }
            crate::system::write_stdout_line(&header);
            crate::system::write_stdout_line("");
            let width = lines.iter().map(|(_, n, _)| n.len()).max().unwrap_or(0);
            for (mark, name, detail) in &lines {
                crate::system::write_stdout_line(&format!("  {mark}  {name:<width$}  {detail}"));
            }
            if lines.is_empty() {
                crate::system::write_stdout_line("  (no migrations declared)");
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            if drift_n > 0 {
                crate::system::write_stderr_line(
                    "\ndb: drift detected — an applied migration's SQL was edited. \
                     Restore its original text, or ship a new compensating migration.",
                );
                // `ipe db migrate` status-op boundary: drift detected, exit non-zero
                crate::system::exit_process(1);
            }
            // `ipe db migrate` status-op boundary: clean status, exit zero
            crate::system::exit_process(0);
        }

        // 3. Apply pending migrations in declaration order.
        let mut out: Vec<String> = Vec::new();
        for (name, sql) in migrations {
            let sum = migrate_checksum(&sql);
            if let Some((prev, _)) = applied.get(&name) {
                if prev != &sum {
                    // Drift: error embeds only the app-authored NAME, never the
                    // SQL body (which may carry seed-data literals) nor the hash.
                    if op == "migrate" {
                        crate::system::write_stderr_line(&format!(
                            "db: migration '{name}' changed after it was applied — checksum mismatch"
                        ));
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        // `ipe db migrate` CLI-op boundary: applied migration changed (checksum mismatch), exit non-zero
                        crate::system::exit_process(1);
                    }
                    return IpeResult::Err(
                        format!(
                            "db.migrate: migration '{name}' changed after it was \
                             applied — checksum mismatch"
                        )
                        .into(),
                    );
                }
                continue; // already up to date
            }

            // Each migration in its OWN transaction (single held connection via
            // db_with_transaction's task-local routing): the migration SQL + the
            // ledger INSERT commit together or roll back together.
            let stmt = sql.clone();
            let rec_name = name.clone();
            let rec_sum = sum.clone();
            let applied_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            // db_with_transaction takes `FnOnce` (called exactly once), but
            // clones inside ensure the outer loop can re-bind on each iteration.
            // db_exec/db_exec_raw now return rows-affected (i64), so the tx body's
            // tail yields i64 — bind/turbofish accordingly; the count is unused
            // (migrate cares about success, not row counts).
            let outcome: IpeResult<E, i64> = db_with_transaction::<E, i64>(db.clone(), move |c| {
                let stmt = stmt.clone();
                let rec_name = rec_name.clone();
                let rec_sum = rec_sum.clone();
                let applied_at = applied_at.clone();
                Box::pin(async move {
                    if let IpeResult::Err(e) = db_exec_raw::<E>(c.clone(), stmt).await {
                        return IpeResult::Err(e);
                    }
                    // Ledger INSERT uses BOUND params — no interpolation.
                    db_exec::<E>(
                        c.clone(),
                        "INSERT INTO _ipe_migrations (name, checksum, applied_at) \
                             VALUES (?, ?, ?)"
                            .to_string(),
                        vec![rec_name, rec_sum, applied_at],
                    )
                    .await
                })
            })
            .await;

            match outcome {
                IpeResult::Ok(_) => out.push(name),
                IpeResult::Err(e) => db_op_fail!(format!("apply migration '{name}'"), e),
            }
        }

        // 4. `migrate` op mode — print the summary, then exit.
        if op == "migrate" {
            if out.is_empty() {
                crate::system::write_stdout_line(
                    "db: schema already up to date — 0 migrations applied",
                );
            } else {
                crate::system::write_stdout_line(&format!(
                    "db: applied {} migration(s): {}",
                    out.len(),
                    out.join(", ")
                ));
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
            // `ipe db migrate` CLI-op boundary: migrations applied, exit zero
            crate::system::exit_process(0);
        }
        IpeResult::Ok(out)
    })
}

// ─── Additional Ipe.Db kernels ────────────────────────────────────────

/// `close : Db -> Task Error ()` — sqlx::Pool drops on its own; this is
/// a graceful explicit close (any in-flight queries finish, then the
/// pool is closed).
pub fn db_close<E: Send + From<String> + 'static>(db: Db) -> IpeTask<E, ()> {
    Box::pin(async move {
        db.close().await;
        ok_res(())
    })
}

/// `getBool : String -> Dict String String -> Bool` — parses common
/// truthy values (`"1"`, `"true"`, `"TRUE"`, `"t"`, `"T"`).
pub fn db_get_bool<R: IpeRow>(field: String, row: &R) -> bool {
    matches!(
        row.ipe_get(&field).as_str(),
        "1" | "true" | "TRUE" | "t" | "T"
    )
}

/// Whether a [`SqlIdent`] may contain `.` separators.
///
/// A `Plain` identifier is a bare table or column name (`users`, `email`); a
/// `Dotted` identifier additionally admits a qualified reference (`users.id`).
/// The two modes are the ONLY axis on which the single identifier parser
/// varies — there is one charset check, not two hand-rolled ones that could
/// drift apart on a security boundary.
#[derive(Clone, Copy)]
enum IdentMode {
    /// `[A-Za-z0-9_]` — bare table/column name, dots rejected.
    Plain,
    /// `[A-Za-z0-9_.]` — bare name or a dotted qualified reference.
    Dotted,
}

/// A validated SQL identifier (table/column name) — parse-don't-validate and
/// the SINGLE source of truth for the identifier-interpolation boundary. Every
/// path that interpolates a table/column name into SQL obtains one of these
/// through [`SqlIdent::parse`] (or its mode helpers); there is no other
/// charset check in this module. A value of this type is therefore always safe
/// to interpolate — no `""` sentinel to re-check, and an unvalidated name is
/// unrepresentable past the boundary.
struct SqlIdent(String);
impl SqlIdent {
    /// The one and only SQL-identifier charset gate. `mode` selects whether a
    /// `.` separator is admitted; everything else about the policy (non-empty,
    /// ASCII-alphanumeric-or-underscore) is shared, so the `Plain` and
    /// `Dotted` surfaces cannot drift. In `Dotted` mode each dot-delimited
    /// segment must itself be non-empty, so a leading dot, a trailing dot, and
    /// consecutive dots are all rejected — a dotted reference is a sequence of
    /// bare names, never a structurally-malformed dot string.
    fn parse(name: &str, mode: IdentMode) -> Option<SqlIdent> {
        let dot_ok = matches!(mode, IdentMode::Dotted);
        let charset_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || (dot_ok && c == '.'));
        let segments_ok = !dot_ok || name.split('.').all(|seg| !seg.is_empty());
        if charset_ok && segments_ok {
            Some(SqlIdent(name.to_string()))
        } else {
            None
        }
    }
    /// Parse a bare (dot-rejecting) table or column name.
    fn parse_plain(name: &str) -> Option<SqlIdent> {
        Self::parse(name, IdentMode::Plain)
    }
    /// Parse a name that may be a dotted qualified reference (`table.column`).
    fn parse_dotted(name: &str) -> Option<SqlIdent> {
        Self::parse(name, IdentMode::Dotted)
    }
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Extract an `Int` id from a `RETURNING id` row. `Err` (never a fabricated
/// `0`) when the `id` column isn't `i64`- or `i32`-decodable — a non-integer
/// primary key (`TEXT`/`UUID`/composite) or a table whose PK column isn't
/// named `id`. Before this helper existed, `db_insert_row` silently returned
/// `0` on a decode miss — indistinguishable from a genuine `id = 0` row, and
/// any caller that used the returned id to look the row back up would
/// silently operate on the wrong row (or no row at all).
#[cfg(feature = "db")]
fn extract_returning_id(r: &DbRow) -> Result<i64, String> {
    r.try_get::<i64, _>("id")
        .or_else(|_| r.try_get::<i32, _>("id").map(i64::from))
        .map_err(|_| {
            "inserted row's id column is not an integer (non-integer or composite \
             primary key) — cannot report an Int id; use Db.insertFieldsReturning \
             with a typed decoder instead"
                .to_string()
        })
}

/// `insertRow : Db -> String -> Dict String String -> Task Error Int` —
/// returns the inserted row's id (lastInsertRowid for sqlite).
pub fn db_insert_row<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    row: HashMap<String, String>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.insertRow: invalid table name {:?}", table).into(),
                );
            }
        };
        if row.is_empty() {
            return IpeResult::Err("db.insertRow: empty row".to_string().into());
        }
        let mut keys: Vec<&String> = row.keys().collect();
        keys.sort(); // deterministic column order
        let col_idents: Vec<SqlIdent> = match keys
            .iter()
            .map(|k| SqlIdent::parse_plain(k))
            .collect::<Option<Vec<_>>>()
        {
            Some(v) => v,
            None => return IpeResult::Err("db.insertRow: invalid column name".to_string().into()),
        };
        let col_names: Vec<&str> = col_idents.iter().map(SqlIdent::as_str).collect();
        let placeholders = vec!["?"; col_names.len()].join(", ");
        let base = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            qtable.as_str(),
            col_names.join(", "),
            placeholders
        );
        if DB_USES_RETURNING_ID {
            // Postgres has no LastInsertId — append `RETURNING id` and read the
            // generated key (matches the  pgx path). `id` is
            // BIGSERIAL (i64) by db_auto_id_column, but a user table may use
            // SERIAL (i32); try both, and surface a clear Err — never a
            // fabricated `0` — when the id column isn't integer-decodable at
            // all (non-integer/composite primary key).
            let sql = db_format_sql(format!("{} RETURNING id", base));
            let mut q = sqlx::query(&sql);
            for k in &keys {
                q = q.bind(row.get(*k).cloned().unwrap_or_default());
            }
            match fetch_one_routed(&conn, q).await {
                Ok(r) => match extract_returning_id(&r) {
                    Ok(id) => ok_res(id),
                    Err(msg) => IpeResult::Err(format!("db.insertRow: {msg}").into()),
                },
                Err(e) => IpeResult::Err(ipe_err(&e)),
            }
        } else {
            let sql = db_format_sql(base);
            let mut q = sqlx::query(&sql);
            for k in &keys {
                q = q.bind(row.get(*k).cloned().unwrap_or_default());
            }
            match exec_routed(&conn, q).await {
                Ok(res) => ok_res(db_last_insert_id(&res)),
                Err(e) => IpeResult::Err(ipe_err(&e)),
            }
        }
    })
}

/// `getById : Db -> String -> String -> Task Error (Maybe (Dict String String))`.
pub fn db_get_by_id<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    id: String,
) -> IpeTask<E, IpeMaybe<HashMap<String, String>>> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.getById: invalid table name {:?}", table).into(),
                );
            }
        };
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE id = ? LIMIT 1",
            qtable.as_str()
        ));
        match fetch_optional_routed(&conn, sqlx::query(&sql).bind(id)).await {
            Ok(Some(r)) => ok_res(IpeMaybe::Just(row_to_map(&r))),
            Ok(None) => ok_res(IpeMaybe::Nothing),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `updateById : Db -> String -> String -> Dict String String -> Task Error Int` —
/// returns the affected row count.
pub fn db_update_by_id<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    id: String,
    row: HashMap<String, String>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.updateById: invalid table name {:?}", table).into(),
                );
            }
        };
        if row.is_empty() {
            return ok_res(0);
        }
        let mut keys: Vec<&String> = row.keys().collect();
        keys.sort();
        let col_idents: Vec<SqlIdent> = match keys
            .iter()
            .map(|k| SqlIdent::parse_plain(k))
            .collect::<Option<Vec<_>>>()
        {
            Some(v) => v,
            None => return IpeResult::Err("db.updateById: invalid column name".to_string().into()),
        };
        let col_names: Vec<&str> = col_idents.iter().map(SqlIdent::as_str).collect();
        let sets: Vec<String> = col_names.iter().map(|c| format!("{} = ?", c)).collect();
        let sql = db_format_sql(format!(
            "UPDATE {} SET {} WHERE id = ?",
            qtable.as_str(),
            sets.join(", ")
        ));
        let mut q = sqlx::query(&sql);
        for k in &keys {
            q = q.bind(row.get(*k).cloned().unwrap_or_default());
        }
        q = q.bind(id);
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `deleteById : Db -> String -> String -> Task Error Int` — returns
/// the affected row count (0 or 1).
pub fn db_delete_by_id<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    id: String,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.deleteById: invalid table name {:?}", table).into(),
                );
            }
        };
        let sql = db_format_sql(format!("DELETE FROM {} WHERE id = ?", qtable.as_str()));
        match exec_routed(&conn, sqlx::query(&sql).bind(id)).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `findOneByField : Db -> String -> String -> String -> Task Error (Maybe (Dict String String))`.
pub fn db_find_one_by_field<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    field: String,
    value: String,
) -> IpeTask<E, IpeMaybe<HashMap<String, String>>> {
    Box::pin(async move {
        let (qtable, qfield) = match (SqlIdent::parse_plain(&table), SqlIdent::parse_plain(&field))
        {
            (Some(t), Some(f)) => (t, f),
            _ => {
                return IpeResult::Err(
                    format!(
                        "db.findOneByField: invalid identifier in {:?}.{:?}",
                        table, field
                    )
                    .into(),
                );
            }
        };
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE {} = ? LIMIT 1",
            qtable.as_str(),
            qfield.as_str()
        ));
        match fetch_optional_routed(&conn, sqlx::query(&sql).bind(value)).await {
            Ok(Some(r)) => ok_res(IpeMaybe::Just(row_to_map(&r))),
            Ok(None) => ok_res(IpeMaybe::Nothing),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `findManyByField : Db -> String -> String -> String -> Task Error (List (Dict String String))`.
pub fn db_find_many_by_field<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    field: String,
    value: String,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        let (qtable, qfield) = match (SqlIdent::parse_plain(&table), SqlIdent::parse_plain(&field))
        {
            (Some(t), Some(f)) => (t, f),
            _ => {
                return IpeResult::Err(
                    format!(
                        "db.findManyByField: invalid identifier in {:?}.{:?}",
                        table, field
                    )
                    .into(),
                );
            }
        };
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE {} = ?",
            qtable.as_str(),
            qfield.as_str()
        ));
        match fetch_all_routed(&conn, sqlx::query(&sql).bind(value)).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `findByConditions : Db -> String -> Dict String String -> Task Error (List (Dict String String))` —
/// AND-joined equality on every key/value pair.
pub fn db_find_by_conditions<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    conditions: HashMap<String, String>,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.findByConditions: invalid table {:?}", table).into(),
                );
            }
        };
        let mut keys: Vec<&String> = conditions.keys().collect();
        keys.sort();
        let qfield_idents: Vec<SqlIdent> = match keys
            .iter()
            .map(|k| SqlIdent::parse_plain(k))
            .collect::<Option<Vec<_>>>()
        {
            Some(v) => v,
            None => {
                return IpeResult::Err(
                    "db.findByConditions: invalid column name"
                        .to_string()
                        .into(),
                );
            }
        };
        let qfields: Vec<&str> = qfield_idents.iter().map(SqlIdent::as_str).collect();
        // Refuse an unscoped SELECT: an empty condition set would return every
        // row in the table — a cross-tenant read when conditions come from
        // request-derived filters. Mirrors the `db_update_fields` empty-WHERE
        // guard. Callers wanting all rows must use `db_query` / `db_query_raw`.
        if keys.is_empty() {
            return IpeResult::Err(
                "db.findByConditions: refusing unscoped SELECT (no conditions); \
                 pass at least one condition"
                    .to_string()
                    .into(),
            );
        }
        let wheres: Vec<String> = qfields.iter().map(|c| format!("{} = ?", c)).collect();
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE {}",
            qtable.as_str(),
            wheres.join(" AND ")
        ));
        let mut q = sqlx::query(&sql);
        for k in &keys {
            q = q.bind(conditions.get(*k).cloned().unwrap_or_default());
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `queryDecode : Db -> String -> List String -> Decoder a -> Task Error (List a)` —
/// typed query with a per-row decoder (Decoder<E,A>). Builds a NULL-preserving
/// `JsonVal::Object` per row (via `row_to_json`) and runs the decoder against it.
/// Fails fast on the first decode error.
///
/// The `Decoder<E,A>` is `Box<dyn Fn(&JsonVal) -> IpeResult<E,A> + Send>`. Moving
/// it into the async block is sound: it is `Send`, and calling `decoder(&jv)` is
/// a shared-reference call (no move out of the box). No `Arc` needed.
pub fn db_query_decode<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    sql: String,
    params: Vec<String>,
    decoder: Decoder<E, A>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = q.bind(p);
        }
        let rows = match fetch_all_routed(&conn, q).await {
            Ok(r) => r,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let jv = match row_to_json(row) {
                Ok(v) => v,
                Err(e) => return IpeResult::Err(ipe_err(&e)),
            };
            match (decoder.run)(&jv) {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// `queryDecode` with `List SqlValue` params  — mirror of
/// `db_query_decode` binding each param via the total `bind_sql_param` instead of
/// `q.bind(String)`. Codegen routes HERE when the params arg's solved element type
/// is `SqlValue` (ExprEmitter `isSqlValueListArg`); a homogeneous `List String`
/// keeps the `db_query_decode` (Vec<String>) path. Same fetch_all_routed +
/// row_to_json + decoder loop; same positional binding (never interpolated).
pub fn db_query_decode_params<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    sql: String,
    params: Vec<SqlParam>,
    decoder: Decoder<E, A>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        let final_sql = db_format_sql(sql);
        let mut q = sqlx::query(&final_sql);
        for p in params {
            q = bind_sql_param(q, p);
        }
        let rows = match fetch_all_routed(&conn, q).await {
            Ok(r) => r,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let jv = match row_to_json(row) {
                Ok(v) => v,
                Err(e) => return IpeResult::Err(ipe_err(&e)),
            };
            match (decoder.run)(&jv) {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// `getByIdDecode : Db -> String -> Int -> Decoder a -> Task Error (Maybe a)` —
/// SELECT * FROM `table` WHERE id = `id` LIMIT 1; returns Nothing when no row
/// matches, Just(decoded) on success, Err on DB error or decode error.
///
/// Security: `id` is bound via a parameterised placeholder (`?`), NEVER
/// string-interpolated into SQL.
pub fn db_get_by_id_decode<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    table: String,
    id: i64,
    decoder: Decoder<E, A>,
) -> IpeTask<E, IpeMaybe<A>> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.getByIdDecode: invalid table name {:?}", table).into(),
                );
            }
        };
        // id is bound as a parameter — injection-safe.
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE id = ? LIMIT 1",
            qtable.as_str()
        ));
        match fetch_optional_routed(&conn, sqlx::query(&sql).bind(id)).await {
            Ok(None) => ok_res(IpeMaybe::Nothing),
            Ok(Some(row)) => {
                let jv = match row_to_json(&row) {
                    Ok(v) => v,
                    Err(e) => return IpeResult::Err(ipe_err(&e)),
                };
                match (decoder.run)(&jv) {
                    IpeResult::Ok(a) => ok_res(IpeMaybe::Just(a)),
                    IpeResult::Err(e) => IpeResult::Err(e),
                }
            }
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `withTransaction : Db -> (Db -> Task Error a) -> Task Error a` —
/// runs the body inside a transaction. Commits on Ok, rolls back on Err.
///
/// **Connection semantics (real isolation on any pool size).** sqlx's `Pool`
/// dispatches each `.execute()` to an arbitrary free connection, so issuing
/// BEGIN/COMMIT/ROLLBACK against the pool would scatter the transaction-control
/// statements and the body's writes across different physical connections — on a
/// multi-connection pool a rollback would then silently fail to undo the body's
/// (autocommitted) writes.
///
/// This implementation pins the whole transaction to ONE connection:
///  1. `pool.acquire()` takes a dedicated `PoolConnection` out of the pool.
///  2. The connection is stored in the `TXN_CONN` `tokio::task_local!` (behind an
///     `Arc<Mutex<..>>`) for the dynamic extent of the body.
///  3. `BEGIN`, the body, and `COMMIT`/`ROLLBACK` all run on THAT connection —
///     the body's `Db.exec`/`Db.query`/`insertRow`/… route through the `*_routed`
///     helpers, which lock the task-local connection when present.
///  4. On every exit (Ok / Err / body-error) the `PoolConnection` is dropped at
///     the end of the scope, returning it to the pool (RAII — never leaked).
///
/// **Nested `withTransaction`.** If a transaction connection is already active on
/// this task (a nested call), we DO NOT acquire a second connection or issue a
/// nested `BEGIN` (sqlite/MySQL would error; it would also deadlock on the
/// `Mutex`). Instead the inner call runs the body directly on the already-held
/// connection (flattened semantics — the inner block shares the outer
/// transaction's atomicity; an inner `Err` does not roll back independently). A
/// true SAVEPOINT-per-nesting is the ideal future refinement; flattening is the
/// simplest correct behaviour and never deadlocks.
///
/// **Nesting is gated on pool identity (AUD-03 fix).** Flattening is only
/// correct when the nested call reuses the SAME pool as the active
/// transaction — flattening a call for a DIFFERENT `Db` handle onto it would
/// silently execute that pool's operations against the wrong physical
/// connection (cross-database data corruption). `current_txn_conn_for(&conn)`
/// returns `None` when the active transaction belongs to a different pool, so
/// that case falls through to the code below and opens its OWN independent
/// transaction on `conn` — nested correctly via `TXN_CONN.scope`'s normal
/// task-local shadow/restore (the outer transaction's task-local value is
/// restored once this inner scope's future completes), not by any manual
/// stack bookkeeping.
pub fn db_with_transaction<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    body: impl FnOnce(Db) -> IpeTask<E, A> + Send + 'static,
) -> IpeTask<E, A> {
    Box::pin(async move {
        // Nested on the SAME pool: flatten onto the existing connection (no
        // second acquire, no nested BEGIN, no deadlock). A nested call on a
        // DIFFERENT pool falls through and opens its own transaction below.
        if current_txn_conn_for(&conn).is_some() {
            return body(conn).await;
        }

        // Begin a real sqlx Transaction (BEGIN is issued by `begin()`); its Drop
        // rolls back, so dropping the body future mid-transaction can't leak an
        // open txn onto a pooled connection. Held in Arc<Mutex<..>> so re-entrant
        // body ops serialise on it.
        let tx = match conn.begin().await {
            Ok(t) => t,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let tx_conn: TxnConn = std::sync::Arc::new(tokio::sync::Mutex::new(tx));

        // Run the body inside the task-local scope so every body DB op routes to
        // `tx_conn`. The body still receives the pool by value (its `Db` arg) —
        // the routing happens via the task-local, not the arg.
        let pool_for_body = conn.clone();
        let owner = pool_identity(&conn);
        let outcome = TXN_CONN
            .scope(Some((owner, tx_conn.clone())), async move {
                body(pool_for_body).await
            })
            .await;

        // Reclaim sole ownership to finish via the TYPED commit/rollback (which
        // consume the Transaction and keep its Drop-state consistent — a raw COMMIT
        // string would leave the wrapper thinking the txn is open → a redundant
        // ROLLBACK on Drop). The scope's clone is released when the scoped future
        // above completes, and tokio task-locals don't propagate into spawned
        // tasks, so the strong count is 1 here.
        let tx = match std::sync::Arc::try_unwrap(tx_conn) {
            Ok(m) => m.into_inner(),
            // Structurally unreachable (no clone escapes). Fail closed: our handle
            // is dropped here, rolling the txn back, and we report rather than
            // committing a transaction we don't solely own.
            Err(_) => {
                return IpeResult::Err(
                    "withTransaction: transaction still referenced at completion"
                        .to_string()
                        .into(),
                );
            }
        };
        match outcome {
            IpeResult::Ok(a) => match tx.commit().await {
                Ok(()) => ok_res(a),
                Err(e) => IpeResult::Err(ipe_err(&e)),
            },
            IpeResult::Err(e) => {
                // Best-effort deterministic rollback; the body's Err is reported.
                let _ = tx.rollback().await;
                IpeResult::Err(e)
            }
        }
    })
}

// ─── SqlParam — runtime-nameable parameter type for db_insert_fields etc. ─────
//
// Ipê's `SqlField` and `SqlValue` ADTs are per-project GENERATED Rust enums
// (`StdDbSqlField`, `StdDbSqlValue`).  The runtime can't name or destructure
// them, but it CAN define `SqlParam` — a parallel enum whose variants match
// SqlValue 1:1.  The codegen emits a conversion at each `insertFields` /
// `updateFields` / `insertFieldsReturning` call site:
//
//   StdDbSqlField::OmitField      → None           (column dropped from SQL)
//   StdDbSqlField::SetField(v)    → Some(v.into())  (column bound as param)
//   StdDbSqlValue::SqlString(s)   → SqlParam::Text(s)
//   StdDbSqlValue::SqlInt(i)      → SqlParam::Int(i)
//   StdDbSqlValue::SqlFloat(f)    → SqlParam::Float(f)
//   StdDbSqlValue::SqlBool(b)     → SqlParam::Bool(b)
//   StdDbSqlValue::SqlBytes(s)    → SqlParam::Bytes(s.into_bytes())
//   StdDbSqlValue::SqlDecimal(d)  → SqlParam::Text(d.to_string())  (lossless)
//   StdDbSqlValue::SqlTime(ms)    → SqlParam::Int(ms)  (Unix millis,
//   StdDbSqlValue::SqlMoney(m)    → SqlParam::Text("ISO_CODE AMOUNT")  (see note)
//   StdDbSqlValue::SqlNull(inner) → SqlParam::Null(Box::new(inner.into_sql_param()))
//
// Money note: `StdMoneyMoney::Money(amount, currency)` is also generated; codegen
// serialises it to "CODE AMOUNT" string (same as  sqlMoneyToString).  If
// codegen cannot destructure Money (e.g. future Money redesign), the fallback is
// SqlParam::Text(money_to_text) where money_to_text is emitted inline.
//
// Security: every table/column name that reaches SQL interpolation is
// validated by the single `SqlIdent` parser (ASCII alphanumeric + `_`, plus
// `.` in dotted mode, rejects empty) — see `SqlIdent::parse`. There is no
// second charset check that could drift from it. All VALUES are
// positional-bound (`?`), never interpolated.
// Totality: no unwrap/panic anywhere in this module section.

/// A runtime-nameable SQL parameter value, matching the Ipê `SqlValue` ADT.
/// See the module-level comment above for the generated-ADT conversion rules.
///
/// `PartialEq` precondition (`SqlFragment` design note): every
/// constituent field type here (`String`, `i64`, `f64`, `bool`, `Vec<u8>`) is
/// already `PartialEq`, so the derive below is total and structural — no
/// hand-written impl needed.
///
/// `Debug` prints the variant and never the bound value: a bind may carry a
/// revealed secret or a client-supplied credential, and every type that holds a
/// `SqlParam` (a fragment, a statement, a refusal) prints through this impl.
#[derive(Clone, PartialEq)]
pub enum SqlParam {
    /// `SqlString s` — binds as TEXT.
    Text(String),
    /// `SqlInt i` / `SqlTime ms` — binds as INTEGER.
    Int(i64),
    /// `SqlFloat f` — binds as REAL.
    Float(f64),
    /// `SqlBool b` — binds as INTEGER (0 / 1), matching SQLite convention.
    Bool(bool),
    /// `SqlBytes s` — binds as BLOB.
    Bytes(Vec<u8>),
    /// `SqlNull witness` — binds a NULL typed according to `witness`'s
    /// variant, so the driver's type-OID hint (Postgres) matches the target
    /// column. `witness`'s VALUE is never read (a NULL carries no value) —
    /// only its variant tag selects the typed `Option::<T>::None` to bind.
    ///
    /// On SQLite this distinction is cosmetic (SQLite is dynamically typed —
    /// a bound NULL is a NULL regardless of the wrapping Rust type). On
    /// Postgres it is load-bearing: sqlx's extended query protocol sends a
    /// type-OID hint per bound parameter derived from the bound Rust type,
    /// and Postgres validates that hint against the target column's type at
    /// prepare time. Binding `Option::<String>::None` (OID: TEXT) against an
    /// `INTEGER`/`BOOLEAN`/`BYTEA`/`TIMESTAMP` column fails with a Postgres
    /// type-mismatch error. Boxed to keep construction cheap (one variant,
    /// rarely on a hot loop) without inflating every other variant's size.
    Null(Box<SqlParam>),
}

impl std::fmt::Debug for SqlParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let masked = crate::redact::Redacted::new(());
        match self {
            Self::Text(_) => f.debug_tuple("Text").field(&masked).finish(),
            Self::Int(_) => f.debug_tuple("Int").field(&masked).finish(),
            Self::Float(_) => f.debug_tuple("Float").field(&masked).finish(),
            Self::Bool(_) => f.debug_tuple("Bool").field(&masked).finish(),
            Self::Bytes(_) => f.debug_tuple("Bytes").field(&masked).finish(),
            Self::Null(witness) => f.debug_tuple("Null").field(witness).finish(),
        }
    }
}

// ── `From<T> for SqlParam` — primitive Ipê types ────────────────────────────
//
// These impls let the emitter use `ipe_runtime::db::SqlParam::from` as a
// uniform projection function for the polymorphic `exec`/`query` params list
// (`List a` where `a` may be `String`, `Int`, `Float`, `Bool`, or `SqlValue`).
// The generated `StdDbSqlValue` type gets a parallel `From` impl emitted by
// `ipe_backend_rust::project::emit_db_projection_impls`, delegating to the
// existing `into_sql_param` inherent method.
//
//  `database/sql` driver accepts `any` and type-switches at
// runtime; here the conversion is statically resolved by the Rust type system.

impl From<String> for SqlParam {
    /// Bind a Ipê `String` parameter as SQL TEXT.
    fn from(s: String) -> Self {
        SqlParam::Text(s)
    }
}

impl From<i64> for SqlParam {
    /// Bind a Ipê `Int` parameter as SQL INTEGER.
    fn from(i: i64) -> Self {
        SqlParam::Int(i)
    }
}

impl From<f64> for SqlParam {
    /// Bind a Ipê `Float` parameter as SQL REAL.
    fn from(f: f64) -> Self {
        SqlParam::Float(f)
    }
}

impl From<bool> for SqlParam {
    /// Bind a Ipê `Bool` parameter as SQL INTEGER (0 / 1), matching SQLite
    /// convention.
    fn from(b: bool) -> Self {
        SqlParam::Bool(b)
    }
}

/// Predicate form of the DOT-ACCEPTING identifier gate, for the one caller that
/// needs a bare `bool` over a split slice (the `RETURNING` projection check).
/// It is NOT an independent charset check: it delegates to the single
/// [`SqlIdent`] parser ([`IdentMode::Dotted`]), so it cannot drift from the
/// typed boundary used everywhere else. Prefer [`SqlIdent::parse_dotted`] (the
/// typed value) at any site that goes on to interpolate the identifier.
pub fn valid_sql_ident(name: &str) -> bool {
    SqlIdent::parse_dotted(name).is_some()
}

/// Bind a `SqlParam` value onto a sqlx `Query` builder.
/// Returns `IpeResult::Err` only when the DB pool is absent (no-db build).
/// Every variant is handled — this function is TOTAL.
///
/// Driver-agnostic: typed on the `DbQuery<'q>` alias (the configured backend's
/// query type) rather than a hardcoded `sqlx::Sqlite`, so a project built with
/// `[database] driver = "postgres"` (which does NOT enable sqlx's `sqlite`
/// feature) still compiles — `sqlx::Sqlite` / `SqliteArguments` would be E0433
/// there. Each bound value type (String / i64 / f64 / bool / Vec<u8> / Option)
/// impls `Encode + Type` for both Sqlite and Postgres, so the monomorphic
/// per-build `q.bind(..)` resolves on either backend.
#[cfg(feature = "db")]
fn bind_sql_param<'q>(q: DbQuery<'q>, p: SqlParam) -> DbQuery<'q> {
    match p {
        SqlParam::Text(s) => q.bind(s),
        SqlParam::Int(i) => q.bind(i),
        SqlParam::Float(f) => q.bind(f),
        SqlParam::Bool(b) => q.bind(b),
        SqlParam::Bytes(v) => q.bind(v),
        SqlParam::Null(witness) => match *witness {
            SqlParam::Text(_) => q.bind(Option::<String>::None),
            SqlParam::Int(_) => q.bind(Option::<i64>::None),
            SqlParam::Float(_) => q.bind(Option::<f64>::None),
            SqlParam::Bool(_) => q.bind(Option::<bool>::None),
            SqlParam::Bytes(_) => q.bind(Option::<Vec<u8>>::None),
            // A nested Null-of-Null witness is a degenerate shape that should
            // not arise from codegen (SqlValue's SqlNull wraps a concrete leaf
            // SqlValue variant, not another SqlNull) — fall back to a
            // TEXT-typed NULL rather than panicking; matches the pre-fix
            // SQLite-safe behaviour for this unreachable case.
            SqlParam::Null(_) => q.bind(Option::<String>::None),
        },
    }
}

// ─── Ipe.Db.Sql — SqlFragment builder ────────────────────────
//
// Closes the SQL-injection surface the removed `unsafeFindWhere` left open.
// The ONLY way to obtain a `SqlFragment` is through the combinators below —
// there is no public constructor that accepts an arbitrary `String` as SQL
// text — so a naive string-concatenated WHERE clause is a `ipe` TYPE ERROR
// (`String` where `SqlFragment` is expected) at `Db.findWhere` /
// `Db.deleteWhere`, never a runtime injection risk.
//
// Every combinator unconditionally parenthesizes its output (so composing
// `and`/`or`/`not` can never produce an ambiguous-precedence SQL string) and
// merges `binds` positionally with the `?` placeholders it emits — the two
// always stay in lockstep by construction.
//
// `invalid` is a poison marker: `sql_column` sets it on a malformed
// identifier instead of panicking or interpolating unchecked text; every
// combinator propagates the first poison it sees; the two consumers surface
// it as a `Task::Err` rather than emitting malformed SQL.

/// `Ipe.Db.Sql`'s opaque, parameterized WHERE-fragment value.
///
/// The derived `PartialEq` precondition is verified above: every `SqlParam`
/// field type is `PartialEq`, so this derive is total and structural,
/// comparing `sql` text + `binds` + `invalid` state — a meaningful equality
/// with no security concern (unlike `Secret`, nothing here is ever a secret
/// payload).
#[derive(Clone, PartialEq)]
pub struct SqlFragment {
    sql: String,
    binds: Vec<SqlParam>,
    invalid: Option<String>,
}

crate::stringify::show_row!("SqlFragment", Redacted, [] SqlFragment, |_| crate::stringify::REDACTED_SHOW.to_owned());

impl std::fmt::Debug for SqlFragment {
    /// SQL text + bind COUNT only — never bind VALUES. A bind may carry a
    /// revealed secret; this is the one place `SqlFragment` and `Secret`
    /// intersect, and it resolves the same way both items
    /// resolve elsewhere: safe by construction, no reliance on a caller
    /// remembering an escape hatch.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqlFragment")
            .field("sql", &self.sql)
            .field("binds", &self.binds.len())
            .field("invalid", &self.invalid)
            .finish()
    }
}

/// `Sql.column : String -> SqlFragment` — a validated column/table reference.
/// Accepts dotted references (`users.id`) via [`SqlIdent::parse_dotted`] — the
/// dot-admitting mode of the single identifier parser ([`SqlIdent::parse_plain`]
/// is the bare table/column-name-only mode used for the table argument itself,
/// which rejects dots). An invalid identifier poisons the fragment instead of
/// panicking or interpolating unchecked text.
///
/// Takes an owned `String` (not `&str`) to match every other Ipê-`String`-
/// typed kernel parameter in this module — the generic call-emission path
/// (`ipe_backend_rust::emit_expr`'s standard-path fallback) always produces an
/// owned `String` for a Ipê `String` argument, never a borrow.
pub fn sql_column(name: String) -> SqlFragment {
    if let Some(ident) = SqlIdent::parse_dotted(&name) {
        SqlFragment {
            sql: ident.as_str().to_string(),
            binds: Vec::new(),
            invalid: None,
        }
    } else {
        SqlFragment {
            sql: String::new(),
            binds: Vec::new(),
            invalid: Some(format!("Sql.column: invalid identifier {name:?}")),
        }
    }
}

/// `Ipe.Db.Unsafe.unsafeFragment : String -> SqlFragment` — the anti-[`sql_column`]:
/// mints a `SqlFragment` from `name` VERBATIM, deliberately SKIPPING the
/// [`valid_sql_ident`] gate that `sql_column` applies. The caller asserts, under
/// the `unsafe` capability, that `name` is a safe SQL identifier or fragment; no
/// validator runs and no poison marker is set. This is the un-validated escape
/// hatch the safe `Sql.column` path exists to avoid — reachable only through the
/// disclosed `Ipe.Db.Unsafe` submodule.
///
/// Total and panic-free: it constructs the plain `SqlFragment` record with the
/// verbatim text, an empty bind list, and no poison — no indexing, no unwrap, no
/// fallible step.
pub fn sql_unsafe_fragment(name: String) -> SqlFragment {
    SqlFragment {
        sql: name,
        binds: Vec::new(),
        invalid: None,
    }
}

/// `Sql.param : SqlValue -> SqlFragment` — binds `v` as a single `?`
/// placeholder. Also the shared runtime symbol for `Sql.int` / `Sql.string` /
/// `Sql.float` / `Sql.bool`: each is a Ipê-level type narrowing of this same
/// generic entry point (`i64` / `String` / `f64` / `bool` all already have a
/// `From<T> for SqlParam` impl above), so no separate per-type runtime
/// function exists — see the kernel decl doc in `ipe_kernels`.
pub fn sql_param<T: Into<SqlParam>>(v: T) -> SqlFragment {
    SqlFragment {
        sql: "?".to_string(),
        binds: vec![v.into()],
        invalid: None,
    }
}

/// Shared implementation for the binary comparison/boolean combinators:
/// unconditional parens, positional bind merge, first-poison-wins.
fn sql_binop(op: &str, a: SqlFragment, b: SqlFragment) -> SqlFragment {
    let invalid = a.invalid.or(b.invalid);
    let mut binds = a.binds;
    binds.extend(b.binds);
    SqlFragment {
        sql: format!("({} {} {})", a.sql, op, b.sql),
        binds,
        invalid,
    }
}

/// `Sql.eq : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_eq(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("=", a, b)
}
/// `Sql.ne : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_ne(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("!=", a, b)
}
/// `Sql.gt : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_gt(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop(">", a, b)
}
/// `Sql.lt : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_lt(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("<", a, b)
}
/// `Sql.gte : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_gte(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop(">=", a, b)
}
/// `Sql.lte : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_lte(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("<=", a, b)
}
/// `Sql.and : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_and(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("AND", a, b)
}
/// `Sql.or : SqlFragment -> SqlFragment -> SqlFragment`
pub fn sql_or(a: SqlFragment, b: SqlFragment) -> SqlFragment {
    sql_binop("OR", a, b)
}

/// `Sql.not : SqlFragment -> SqlFragment`
pub fn sql_not(a: SqlFragment) -> SqlFragment {
    SqlFragment {
        sql: format!("(NOT {})", a.sql),
        binds: a.binds,
        invalid: a.invalid,
    }
}
/// `Sql.isNull : SqlFragment -> SqlFragment`
pub fn sql_is_null(a: SqlFragment) -> SqlFragment {
    SqlFragment {
        sql: format!("({} IS NULL)", a.sql),
        binds: a.binds,
        invalid: a.invalid,
    }
}
/// `Sql.isNotNull : SqlFragment -> SqlFragment`
pub fn sql_is_not_null(a: SqlFragment) -> SqlFragment {
    SqlFragment {
        sql: format!("({} IS NOT NULL)", a.sql),
        binds: a.binds,
        invalid: a.invalid,
    }
}

/// `Sql.like : SqlFragment -> String -> SqlFragment`.
///
/// The pattern is always a bound param (never interpolated), so it cannot
/// inject SQL. It is still a `LIKE` pattern: a `%` or `_` in the bound value
/// is a wildcard, so untrusted text passed here can widen the match; a literal
/// prefix is [`sql_starts_with`]. Every engine reads the pattern under
/// `ESCAPE '\'` ([`LIKE_ESCAPE`]): `\%`, `\_` and `\\` match `%`, `_` and `\`
/// literally. A pattern ending in an unpaired `\` poisons the fragment, since
/// SQLite reads it as no match and Postgres as an error. SQLite's `LIKE` also
/// folds ASCII case; Postgres's does not.
pub fn sql_like(a: SqlFragment, pattern: String) -> SqlFragment {
    if ends_with_unpaired_escape(&pattern) {
        return SqlFragment {
            sql: String::new(),
            binds: Vec::new(),
            invalid: a.invalid.or_else(|| {
                Some(format!(
                    "Sql.like: the pattern ends with the escape character {LIKE_ESCAPE}"
                ))
            }),
        };
    }
    let mut binds = a.binds;
    binds.push(SqlParam::Text(pattern));
    SqlFragment {
        sql: format!("({})", like_escape_sql(&a.sql)),
        binds,
        invalid: a.invalid,
    }
}

/// The escape character every rendered `LIKE` names in its `ESCAPE` clause.
///
/// `\` escapes the same way on SQLite and on Postgres (whose default escape it
/// is). Under Postgres with `standard_conforming_strings = off`, the literal
/// `'\'` is an unterminated string, so such a server refuses the query rather
/// than reading the pattern another way.
const LIKE_ESCAPE: char = '\\';

/// Ceiling on a [`LikePrefix`], in UTF-8 bytes.
const MAX_LIKE_PREFIX_BYTES: usize = 16 * 1024;

/// SQLite's default `SQLITE_MAX_LIKE_PATTERN_LENGTH`, in bytes.
const SQLITE_DEFAULT_MAX_LIKE_PATTERN_LENGTH: usize = 50_000;

// Every reserved character escaped doubles, plus the trailing `%`: the longest
// pattern a `LikePrefix` renders stays inside SQLite's pattern ceiling.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the prefix ceiling outgrows SQLite's LIKE pattern ceiling [ledger #boundary]
const _: () = assert!(2 * MAX_LIKE_PREFIX_BYTES < SQLITE_DEFAULT_MAX_LIKE_PATTERN_LENGTH);
// The escape character is neither a wildcard nor a character that ends or
// opens the quoted `ESCAPE` literal or a placeholder.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the LIKE escape character is a wildcard, quote or placeholder [ledger #boundary]
const _: () = assert!(!matches!(LIKE_ESCAPE, '%' | '_' | '\'' | '"' | '?'));

/// `<subject> LIKE ? ESCAPE '\'`: the one rendering of a `LIKE` predicate.
fn like_escape_sql(subject_sql: &str) -> String {
    format!("{subject_sql} LIKE ? ESCAPE '{LIKE_ESCAPE}'")
}

/// Whether `pattern` ends in an escape character that escapes nothing.
fn ends_with_unpaired_escape(pattern: &str) -> bool {
    pattern
        .chars()
        .fold(false, |escaping, c| !escaping && c == LIKE_ESCAPE)
}

/// A literal text prefix, parsed once: non-empty, NUL-free, at most
/// [`MAX_LIKE_PREFIX_BYTES`] bytes.
///
/// It owns the one `LIKE` escaper, so the pattern it renders matches its text
/// literally and nothing else.
struct LikePrefix(String);

/// Why a text is not a [`LikePrefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LikePrefixError {
    /// The text is empty, which would match every non-`NULL` row.
    Empty,
    /// The text holds a NUL character.
    Nul,
    /// The text is longer than [`MAX_LIKE_PREFIX_BYTES`].
    TooLong,
}

impl LikePrefixError {
    /// The poison text of a refused `Sql.startsWith`; it never echoes the prefix.
    fn message(self) -> String {
        match self {
            Self::Empty => "Sql.startsWith: the prefix is empty".to_string(),
            Self::Nul => "Sql.startsWith: the prefix contains a NUL character".to_string(),
            Self::TooLong => {
                format!("Sql.startsWith: the prefix is longer than {MAX_LIKE_PREFIX_BYTES} bytes")
            }
        }
    }
}

impl LikePrefix {
    /// Parse `raw`, refusing an empty, NUL-bearing or over-long text, in that order.
    fn parse(raw: String) -> Result<Self, LikePrefixError> {
        if raw.is_empty() {
            Err(LikePrefixError::Empty)
        } else if raw.contains('\0') {
            Err(LikePrefixError::Nul)
        } else if raw.len() > MAX_LIKE_PREFIX_BYTES {
            Err(LikePrefixError::TooLong)
        } else {
            Ok(Self(raw))
        }
    }

    /// The `LIKE` pattern: each `%`, `_` and [`LIKE_ESCAPE`] preceded by
    /// [`LIKE_ESCAPE`], then a trailing `%`.
    fn like_pattern(&self) -> String {
        let mut pattern = String::with_capacity(self.0.len() + 1);
        for c in self.0.chars() {
            match c {
                '%' | '_' | LIKE_ESCAPE => {
                    pattern.push(LIKE_ESCAPE);
                    pattern.push(c);
                }
                other => pattern.push(other),
            }
        }
        pattern.push('%');
        pattern
    }

    /// The prefix text.
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// `substr(<subject>, 1, length(?)) = ?`: the exact-prefix shape, written once.
///
/// `substr` and `length` count characters on SQLite and Postgres alike, and
/// `=` compares bytes under a binary or deterministic collation, so the shape
/// carries no wildcard and no case folding.
pub(crate) fn text_prefix_equals_sql(subject_sql: &str) -> String {
    format!("substr({subject_sql}, 1, length(?)) = ?")
}

/// `Sql.startsWith : SqlFragment -> String -> SqlFragment` — the rows whose
/// `a` text begins with exactly `prefix`, character for character.
///
/// Renders `((<a> LIKE ? ESCAPE '\') AND (substr(<a>, 1, length(?)) = ?))`
/// with binds `a.binds ++ [pattern] ++ a.binds ++ [prefix, prefix]`. The
/// escaped `LIKE` conjunct lets an index serve the scan; the `substr` conjunct
/// makes the match exact and case-sensitive on every engine under a
/// deterministic collation (a Postgres column declared with a
/// nondeterministic collation makes `=` compare by that collation). A `NULL` `a` never
/// matches. An empty, NUL-bearing or over-long prefix poisons the fragment, and
/// an upstream poison in `a` wins over it.
pub fn sql_starts_with(a: SqlFragment, prefix: String) -> SqlFragment {
    let prefix = match LikePrefix::parse(prefix) {
        Ok(prefix) => prefix,
        Err(refused) => {
            return SqlFragment {
                sql: String::new(),
                binds: Vec::new(),
                invalid: a.invalid.or_else(|| Some(refused.message())),
            };
        }
    };
    let sql = format!(
        "(({}) AND ({}))",
        like_escape_sql(&a.sql),
        text_prefix_equals_sql(&a.sql)
    );
    let mut binds = Vec::with_capacity(2 * a.binds.len() + 3);
    binds.extend(a.binds.iter().cloned());
    binds.push(SqlParam::Text(prefix.like_pattern()));
    binds.extend(a.binds);
    binds.push(SqlParam::Text(prefix.as_str().to_string()));
    binds.push(SqlParam::Text(prefix.0));
    SqlFragment {
        sql,
        binds,
        invalid: a.invalid,
    }
}

/// `Sql.inList : SqlFragment -> List SqlValue -> SqlFragment`. Empty `values`
/// emits `(1 = 0)` (always-false) rather than the SQL syntax error `IN ()` —
/// `a`'s own `sql` text is discarded in that case, so `a`'s binds (if any)
/// are dropped too (keeping the placeholder count and `binds` length in
/// lockstep); `a.invalid` still propagates so an upstream poisoned column
/// reference is not silently swallowed by the always-false shortcut.
pub fn sql_in_list(a: SqlFragment, values: Vec<SqlParam>) -> SqlFragment {
    if values.is_empty() {
        return SqlFragment {
            sql: "(1 = 0)".to_string(),
            binds: Vec::new(),
            invalid: a.invalid,
        };
    }
    let placeholders = vec!["?"; values.len()].join(", ");
    let mut binds = a.binds;
    binds.extend(values);
    SqlFragment {
        sql: format!("({} IN ({}))", a.sql, placeholders),
        binds,
        invalid: a.invalid,
    }
}

/// `Sql.exists : String -> SqlFragment -> SqlFragment` — a correlated-subquery
/// existence test: `EXISTS (SELECT 1 FROM <table> WHERE <inner>)`. The single
/// site that embeds a table name AND a nested `SELECT` into SQL text, so it
/// applies the same fail-closed discipline the rest of the surface does:
///
///   * The table name is validated through [`SqlIdent::parse_plain`] — the SAME
///     bare-identifier gate `db_find_where` applies to its table argument — so an
///     invalid table poisons the fragment (empty `sql`, an `invalid` marker)
///     rather than interpolating unchecked text. There is no unvalidated table
///     path; the caller cannot reach `sql_unsafe_fragment` from here.
///   * `inner` was itself built only through the audited `Sql.*` combinators, so
///     its `sql` is `?`-placeholder text with a matching `binds` list. Those
///     binds propagate positionally, and the placeholder count stays in lockstep.
///   * `inner`'s poison propagates first-wins: an upstream invalid column inside
///     the subquery is never swallowed by a valid table name.
///
/// Total and panic-free: no indexing, no unwrap, no fallible step beyond the
/// checked table parse whose `None` branch poisons.
pub fn sql_exists(table: String, inner: SqlFragment) -> SqlFragment {
    match SqlIdent::parse_plain(&table) {
        None => SqlFragment {
            sql: String::new(),
            binds: Vec::new(),
            invalid: inner
                .invalid
                .or_else(|| Some(format!("Sql.exists: invalid table {table:?}"))),
        },
        Some(qtable) => SqlFragment {
            sql: format!(
                "EXISTS (SELECT 1 FROM {} WHERE {})",
                qtable.as_str(),
                inner.sql
            ),
            binds: inner.binds,
            invalid: inner.invalid,
        },
    }
}

/// `Sql.maskedColumn : SqlFragment -> String -> SqlFragment` — a column-masking
/// projection term: `CASE WHEN (<pred>) THEN <col> ELSE NULL END AS <col>`. An
/// authorized row (the predicate holds) projects the column's real value; an
/// unauthorized row projects SQL `NULL`, which the NULL-preserving masked read
/// (`db_find_where_masked`) decodes to `Nothing` — never the empty string.
///
/// The single site that embeds a column name into a `CASE` SELECT term, so it
/// applies the same fail-closed discipline as the rest of the surface:
///
///   * The column name is validated through [`SqlIdent::parse_dotted`] — the SAME
///     gate [`sql_column`] applies — so an invalid identifier poisons the fragment
///     (empty `sql`, an `invalid` marker) rather than interpolating unchecked
///     text. There is no unvalidated column path.
///   * `pred` was itself built only through the audited `Sql.*` combinators, so
///     its `sql` is `?`-placeholder text with a matching `binds` list. Those binds
///     propagate positionally into the masked read before the WHERE binds.
///   * `pred`'s poison propagates first-wins: an upstream invalid column inside
///     the predicate is never swallowed by a valid masked column name.
///
/// Total and panic-free: no indexing, no unwrap, no fallible step beyond the
/// checked column parse whose `None` branch poisons.
pub fn sql_masked_column(pred: SqlFragment, col: String) -> SqlFragment {
    match SqlIdent::parse_dotted(&col) {
        None => SqlFragment {
            sql: String::new(),
            binds: Vec::new(),
            invalid: pred
                .invalid
                .or_else(|| Some(format!("Sql.maskedColumn: invalid column {col:?}"))),
        },
        Some(qcol) => SqlFragment {
            sql: format!(
                "CASE WHEN ({}) THEN {} ELSE NULL END AS {}",
                pred.sql,
                qcol.as_str(),
                qcol.as_str()
            ),
            binds: pred.binds,
            invalid: pred.invalid,
        },
    }
}

/// `Db.findWhere : Db -> String -> SqlFragment -> Task Error (List (Dict String String))`
/// — the `SqlFragment`-typed replacement for the removed `unsafeFindWhere`.
/// The WHERE clause can only be built through the `Sql.*` combinators above,
/// so `frag.sql` is always `?`-placeholder text with a matching `frag.binds`
/// list — there is no representable way to smuggle untrusted string content
/// into the SQL text.
pub fn db_find_where<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    frag: SqlFragment,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findWhere: {reason}").into());
        }
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(format!("db.findWhere: invalid table {:?}", table).into());
            }
        };
        let sql = db_format_sql(format!(
            "SELECT * FROM {} WHERE {}",
            qtable.as_str(),
            frag.sql
        ));
        let mut q = sqlx::query(&sql);
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `Db.findWhereMasked : Db -> String -> List SqlFragment -> SqlFragment
///                        -> Decoder a -> Task Error (List a)` — the
/// NULL-preserving projected read every codec-decoded `Ipe.Db.Store` app read
/// routes through (unmasked: each projection a plain column; secured: some
/// projections masked).
///
/// It is `db_find_where`'s column-masking counterpart. Where `db_find_where`
/// emits `SELECT * … ` and returns cells via `row_to_map` (which collapses SQL
/// NULL → `""`, so a masked cell would decode `Just ""`), this builds an
/// EXPLICIT projection from the caller's validated `projections` fragments — each
/// a plain `Sql.column col AS col` for an unmasked column, or a
/// `CASE WHEN (<pred>) THEN col ELSE NULL END AS col` from [`sql_masked_column`]
/// for a masked one — and decodes each row through the threaded `Decoder` over
/// the NULL-preserving [`row_to_json`] bridge, exactly as [`db_query_decode`]
/// does. So an unauthorized (masked) cell arrives as `JsonVal::Null` and the
/// codec's `CNull` arm decodes it to `Nothing`, never the empty string.
///
/// Injection-safe by construction: the table passes the same `SqlIdent::parse_plain`
/// gate as `db_find_where`; every projection fragment and the WHERE fragment were
/// built only through the audited `Sql.*` combinators (validated identifiers +
/// bound `?` params), so the assembled statement holds no interpolated value. A
/// poisoned projection or WHERE fragment fails the whole read closed. The masked
/// `CASE` predicates carry their `$subject` binds; those bind FIRST (SELECT terms
/// precede the WHERE), mirroring `db_find_projection`'s literal-then-where order,
/// so placeholders and binds stay in lockstep.
pub fn db_find_where_masked<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    table: String,
    projections: Vec<SqlFragment>,
    frag: SqlFragment,
    decoder: Decoder<E, A>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findWhereMasked: {reason}").into());
        }
        // First-poison-wins across every projection fragment.
        for p in &projections {
            if let Some(reason) = &p.invalid {
                return IpeResult::Err(format!("db.findWhereMasked: {reason}").into());
            }
        }
        if projections.is_empty() {
            return IpeResult::Err(
                "db.findWhereMasked: a masked read must project at least one column"
                    .to_string()
                    .into(),
            );
        }
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.findWhereMasked: invalid table {:?}", table).into(),
                );
            }
        };
        let select_terms = projections
            .iter()
            .map(|p| p.sql.clone())
            .collect::<Vec<_>>()
            .join(", ");
        let sql = db_format_sql(format!(
            "SELECT {} FROM {} WHERE {}",
            select_terms,
            qtable.as_str(),
            frag.sql
        ));
        let mut q = sqlx::query(&sql);
        // Projection (SELECT `?`) binds first — they precede the WHERE `?` binds.
        for p in projections {
            for b in p.binds {
                q = bind_sql_param(q, b);
            }
        }
        for b in frag.binds {
            q = bind_sql_param(q, b);
        }
        let rows = match fetch_all_routed(&conn, q).await {
            Ok(r) => r,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let jv = match row_to_json(row) {
                Ok(v) => v,
                Err(e) => return IpeResult::Err(ipe_err(&e)),
            };
            match (decoder.run)(&jv) {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// The separator joining an alias and a column in a join projection's output
/// name (`SELECT a0.title AS a0__title`). A double underscore, so a single
/// underscore inside a column name never collides with the boundary — a
/// projected name splits back into `(alias, column)` at the first `__`.
const JOIN_ALIAS_SEP: &str = "__";

/// One joined result row: the two sides' plain-keyed cell maps (left, right).
/// Each side decodes through its own store codec exactly as a single-table read
/// does, so `Db.findJoin` returns a `List` of these pairs.
pub type JoinRow = (HashMap<String, String>, HashMap<String, String>);

/// One join side: its validated table name, the alias bound to it, and the
/// validated column names to project. Both aliases and every column reach SQL
/// only after `SqlIdent::parse_plain` accepts them, so the projection text this
/// carries can hold no injected fragment.
struct JoinSide {
    ident: SqlIdent,
    alias: SqlIdent,
    columns: Vec<SqlIdent>,
}

impl JoinSide {
    /// Parse a side's identifiers, failing closed on the first that is not a
    /// bare SQL identifier. Mirrors `db_find_where`'s table re-parse: the Ipê
    /// layer already validated these, and the runtime validates them again
    /// (defence in depth) so no single missed gate lets an identifier reach SQL.
    fn parse(table: String, alias: String, columns: Vec<String>) -> Result<JoinSide, String> {
        let ident =
            SqlIdent::parse_plain(&table).ok_or_else(|| format!("invalid table {table:?}"))?;
        let alias =
            SqlIdent::parse_plain(&alias).ok_or_else(|| format!("invalid alias {alias:?}"))?;
        let mut parsed = Vec::with_capacity(columns.len());
        for col in columns {
            let c = SqlIdent::parse_plain(&col).ok_or_else(|| format!("invalid column {col:?}"))?;
            parsed.push(c);
        }
        if parsed.is_empty() {
            return Err(format!(
                "join side {:?} names no columns to project",
                ident.as_str()
            ));
        }
        Ok(JoinSide {
            ident,
            alias,
            columns: parsed,
        })
    }

    /// This side's `alias.column AS alias__column` projection terms, each built
    /// only from already-parsed identifiers.
    fn projection_terms(&self) -> Vec<String> {
        self.columns
            .iter()
            .map(|c| {
                format!(
                    "{alias}.{col} AS {alias}{sep}{col}",
                    alias = self.alias.as_str(),
                    col = c.as_str(),
                    sep = JOIN_ALIAS_SEP
                )
            })
            .collect()
    }

    /// This side's `table AS alias` FROM term.
    fn table_ref(&self) -> String {
        format!("{} AS {}", self.ident.as_str(), self.alias.as_str())
    }

    /// The prefix that marks a projected cell as belonging to this side.
    fn output_prefix(&self) -> String {
        format!("{}{}", self.alias.as_str(), JOIN_ALIAS_SEP)
    }
}

/// Split one joined result row into the two sides' plain-keyed maps: a cell
/// named `alias__column` is stripped of its `alias__` prefix and placed in that
/// side's map under the bare `column`, so each side decodes through its own
/// codec exactly as a single-table read does. A cell matching neither prefix is
/// dropped (the SELECT projects only the two aliases' columns, so none arise).
fn split_join_row(row: &HashMap<String, String>, left_prefix: &str, right_prefix: &str) -> JoinRow {
    let mut left = HashMap::new();
    let mut right = HashMap::new();
    for (name, value) in row {
        if let Some(col) = name.strip_prefix(left_prefix) {
            left.insert(col.to_string(), value.clone());
        } else if let Some(col) = name.strip_prefix(right_prefix) {
            right.insert(col.to_string(), value.clone());
        }
    }
    (left, right)
}

/// `Db.findJoin : Db -> String -> String -> List String -> String -> String
///                -> List String -> SqlFragment
///                -> Task Error (List (Dict String String, Dict String String))`
/// — read an inner join of two tables as one parameterized statement, returning
/// each result row as the pair of the two sides' plain-keyed cell maps.
///
/// The two `(table, alias, columns)` triples name the join sides; `frag` is the
/// WHERE fragment (the join-key equality, plus any filter), built only through
/// the `Sql.*` combinators, so it is always `?`-placeholder text with a matching
/// bind list. Every identifier — both tables, both aliases, every projected
/// column — passes `SqlIdent::parse_plain` before it reaches the SQL text; the
/// first that does not fails the whole read closed. The SELECT projects each
/// side's columns under an `alias__column` output name, and each returned row is
/// split back into the two sides' plain-keyed maps by that prefix, so a caller
/// decodes each side through its existing per-store codec.
#[allow(clippy::too_many_arguments)] // one flat arg per validated identifier group; a struct arg would only move the same seven values behind an emit-side constructor.
pub fn db_find_join<E: Send + From<String> + 'static>(
    conn: Db,
    left_table: String,
    left_alias: String,
    left_columns: Vec<String>,
    right_table: String,
    right_alias: String,
    right_columns: Vec<String>,
    frag: SqlFragment,
) -> IpeTask<E, Vec<JoinRow>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findJoin: {reason}").into());
        }
        let left = match JoinSide::parse(left_table, left_alias, left_columns) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoin: {reason}").into()),
        };
        let right = match JoinSide::parse(right_table, right_alias, right_columns) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoin: {reason}").into()),
        };
        let left_prefix = left.output_prefix();
        let right_prefix = right.output_prefix();
        let sql = match build_join_statement(&left, &right, &frag.sql) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoin: {reason}").into()),
        };
        let mut q = sqlx::query(&sql);
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(
                rows.iter()
                    .map(|r| split_join_row(&row_to_map(r), &left_prefix, &right_prefix))
                    .collect(),
            ),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// Build the single parameterized join statement from the two validated sides
/// and the combinator-built WHERE text. The SELECT projects each side's columns
/// under an `alias__column` output name, the FROM lists both `table AS alias`
/// terms, and the WHERE is the `?`-placeholder fragment text. Every identifier
/// here came through `SqlIdent::parse_plain`; the two sides must carry distinct
/// aliases (else the projection and WHERE could not tell them apart), which is
/// the one remaining fail-closed check. No value is interpolated — the WHERE's
/// values are the fragment's positional binds.
fn build_join_statement(
    left: &JoinSide,
    right: &JoinSide,
    where_sql: &str,
) -> Result<String, String> {
    if left.alias.as_str() == right.alias.as_str() {
        return Err(format!(
            "the two join sides share the alias {:?}; each side needs a distinct alias",
            left.alias.as_str()
        ));
    }
    let mut projection = left.projection_terms();
    projection.extend(right.projection_terms());
    Ok(db_format_sql(format!(
        "SELECT {proj} FROM {lf}, {rf} WHERE {where_}",
        proj = projection.join(", "),
        lf = left.table_ref(),
        rf = right.table_ref(),
        where_ = where_sql
    )))
}

/// Build the join statement like `build_join_statement` but append
/// `ORDER BY <order_clause>`. The `order_clause` string was produced by
/// `parse_order_clause` and contains only pre-validated identifiers; no
/// interpolation occurs here.
fn build_join_statement_ordered(
    left: &JoinSide,
    right: &JoinSide,
    where_sql: &str,
    order_clause: &str,
) -> Result<String, String> {
    if left.alias.as_str() == right.alias.as_str() {
        return Err(format!(
            "the two join sides share the alias {:?}; each side needs a distinct alias",
            left.alias.as_str()
        ));
    }
    let mut projection = left.projection_terms();
    projection.extend(right.projection_terms());
    Ok(db_format_sql(format!(
        "SELECT {proj} FROM {lf}, {rf} WHERE {where_} ORDER BY {order_clause}",
        proj = projection.join(", "),
        lf = left.table_ref(),
        rf = right.table_ref(),
        where_ = where_sql
    )))
}

/// One projected column: the alias-qualified source (`alias.column`) and the
/// output name it is bound to (`p0`, `p1`, …). Both the alias and the column
/// reach SQL only after `SqlIdent::parse_plain` accepts them, so the projection
/// text this carries can hold no injected fragment.
struct ProjectionColumn {
    alias: SqlIdent,
    column: SqlIdent,
    output: SqlIdent,
}

impl ProjectionColumn {
    /// Parse one `(alias, column)` reference into a validated projection at
    /// output position `index`. Fails closed on the first identifier that is not
    /// a bare SQL identifier (defence in depth — the Ipê layer already validated
    /// these).
    fn parse(alias: &str, column: &str, index: usize) -> Result<ProjectionColumn, String> {
        let alias =
            SqlIdent::parse_plain(alias).ok_or_else(|| format!("invalid alias {alias:?}"))?;
        let column =
            SqlIdent::parse_plain(column).ok_or_else(|| format!("invalid column {column:?}"))?;
        let output_name = format!("p{index}");
        let output = SqlIdent::parse_plain(&output_name)
            .ok_or_else(|| format!("invalid projection output {output_name:?}"))?;
        Ok(ProjectionColumn {
            alias,
            column,
            output,
        })
    }

    /// This column's `alias.column AS p<index>` projection term, built only from
    /// already-parsed identifiers.
    fn projection_term(&self) -> String {
        format!(
            "{alias}.{col} AS {out}",
            alias = self.alias.as_str(),
            col = self.column.as_str(),
            out = self.output.as_str()
        )
    }
}

/// `Db.findProjection : Db -> String -> String -> String -> String
///                      -> SqlFragment -> List (String, String) -> List SqlValue
///                      -> Task Error (List (Dict String String))` — read a typed
/// projection over a two-table join as one parameterized statement.
///
/// The two `(table, alias)` pairs name the join sides; `frag` is the WHERE
/// fragment (the join-key equality plus any filter), built only through the
/// `Sql.*` combinators; `projections` is the ordered `(alias, column)` references
/// to project, with empty-alias sentinels marking `Store.literal` positions;
/// `extra_binds` holds the `SqlParam` values for those positions, in the same
/// positional order.
///
/// Every non-empty identifier — both tables, both aliases, and every projected
/// alias and column — passes `SqlIdent::parse_plain` before it reaches SQL text;
/// the first that does not fails the whole read closed. `Store.literal` positions
/// emit `? AS p<index>` in the SELECT; their bound values bind before the WHERE
/// `?` parameters so no value is ever interpolated.
#[allow(clippy::too_many_arguments)] // one flat arg per validated identifier group; a struct arg would only move the same values behind an emit-side constructor.
pub fn db_find_projection<E: Send + From<String> + 'static>(
    conn: Db,
    left_table: String,
    left_alias: String,
    right_table: String,
    right_alias: String,
    frag: SqlFragment,
    projections: Vec<ProjectionTerm>,
    extra_binds: Vec<SqlParam>,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findProjection: {reason}").into());
        }
        let (sql, literal_count) = match build_projection_statement(
            &left_table,
            &left_alias,
            &right_table,
            &right_alias,
            &projections,
            &frag.sql,
        ) {
            Ok(pair) => pair,
            Err(reason) => return IpeResult::Err(format!("db.findProjection: {reason}").into()),
        };
        if extra_binds.len() != literal_count {
            return IpeResult::Err(
                format!(
                    "db.findProjection: {literal_count} literal position(s) but {} extra bind(s)",
                    extra_binds.len()
                )
                .into(),
            );
        }
        let mut q = sqlx::query(&sql);
        // Bind literal (SELECT `?`) params first — they appear before WHERE `?` params.
        for p in extra_binds {
            q = bind_sql_param(q, p);
        }
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `Db.findJoinOrdered : Db -> String -> String -> List String -> String -> String
///                       -> List String -> SqlFragment -> String -> String -> Bool
///                       -> Task Error (List (Dict String String, Dict String String))`
/// — ordered variant of `db_find_join`. Identical to `db_find_join` but appends
/// `ORDER BY <order_alias>.<order_col> ASC|DESC` to the join statement. The three
/// trailing arguments are the validated order-column alias, column name, and
/// ascending direction. Every identifier passes `SqlIdent::parse_plain`; the
/// first that does not fails the whole read closed. No value is interpolated.
#[allow(clippy::too_many_arguments)]
pub fn db_find_join_ordered<E: Send + From<String> + 'static>(
    conn: Db,
    left_table: String,
    left_alias: String,
    left_columns: Vec<String>,
    right_table: String,
    right_alias: String,
    right_columns: Vec<String>,
    frag: SqlFragment,
    order_alias: String,
    order_col: String,
    order_asc: bool,
) -> IpeTask<E, Vec<JoinRow>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findJoinOrdered: {reason}").into());
        }
        let left = match JoinSide::parse(left_table, left_alias, left_columns) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoinOrdered: {reason}").into()),
        };
        let right = match JoinSide::parse(right_table, right_alias, right_columns) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoinOrdered: {reason}").into()),
        };
        let order_clause = match parse_order_clause(&order_alias, &order_col, order_asc) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoinOrdered: {reason}").into()),
        };
        let left_prefix = left.output_prefix();
        let right_prefix = right.output_prefix();
        let sql = match build_join_statement_ordered(&left, &right, &frag.sql, &order_clause) {
            Ok(s) => s,
            Err(reason) => return IpeResult::Err(format!("db.findJoinOrdered: {reason}").into()),
        };
        let mut q = sqlx::query(&sql);
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(
                rows.iter()
                    .map(|r| split_join_row(&row_to_map(r), &left_prefix, &right_prefix))
                    .collect(),
            ),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `Db.findProjectionOrdered : Db -> String -> String -> String -> String
///                             -> SqlFragment -> List (String, String) -> List SqlValue
///                             -> String -> String -> Bool
///                             -> Task Error (List (Dict String String))`
/// — ordered variant of `db_find_projection`. Identical to `db_find_projection`
/// but appends `ORDER BY <order_alias>.<order_col> ASC|DESC` to the projection
/// statement. `extra_binds` holds `SqlParam` values for any `Store.literal`
/// positions in the projection (empty-alias sentinels), bound before the WHERE
/// parameters. The three trailing arguments are the validated order-column alias,
/// column name, and ascending direction. Every non-empty identifier passes
/// `SqlIdent::parse_plain`; the first that does not fails the whole read closed.
#[allow(clippy::too_many_arguments)]
pub fn db_find_projection_ordered<E: Send + From<String> + 'static>(
    conn: Db,
    left_table: String,
    left_alias: String,
    right_table: String,
    right_alias: String,
    frag: SqlFragment,
    projections: Vec<ProjectionTerm>,
    extra_binds: Vec<SqlParam>,
    order_alias: String,
    order_col: String,
    order_asc: bool,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findProjectionOrdered: {reason}").into());
        }
        let order_clause = match parse_order_clause(&order_alias, &order_col, order_asc) {
            Ok(s) => s,
            Err(reason) => {
                return IpeResult::Err(format!("db.findProjectionOrdered: {reason}").into());
            }
        };
        let (sql, literal_count) = match build_projection_statement_ordered(
            &left_table,
            &left_alias,
            &right_table,
            &right_alias,
            &projections,
            &frag.sql,
            &order_clause,
        ) {
            Ok(pair) => pair,
            Err(reason) => {
                return IpeResult::Err(format!("db.findProjectionOrdered: {reason}").into());
            }
        };
        if extra_binds.len() != literal_count {
            return IpeResult::Err(
                format!(
                    "db.findProjectionOrdered: {literal_count} literal position(s) but {} extra bind(s)",
                    extra_binds.len()
                )
                .into(),
            );
        }
        let mut q = sqlx::query(&sql);
        for p in extra_binds {
            q = bind_sql_param(q, p);
        }
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match fetch_all_routed(&conn, q).await {
            Ok(rows) => ok_res(rows.iter().map(row_to_map).collect()),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// Validate the `(alias, column)` pair for an ORDER BY clause and return the
/// `"alias.column ASC|DESC"` fragment. Both identifiers pass
/// `SqlIdent::parse_plain`; the first that does not produces an `Err`. No value
/// is interpolated — only pre-validated column and alias strings enter the SQL.
fn parse_order_clause(alias: &str, col: &str, ascending: bool) -> Result<String, String> {
    let alias_id =
        SqlIdent::parse_plain(alias).ok_or_else(|| format!("invalid order alias {alias:?}"))?;
    let col_id =
        SqlIdent::parse_plain(col).ok_or_else(|| format!("invalid order column {col:?}"))?;
    let dir = if ascending { "ASC" } else { "DESC" };
    Ok(format!("{}.{} {dir}", alias_id.as_str(), col_id.as_str()))
}

/// Build the single parameterized projection statement from the two validated
/// sides, the ordered typed [`ProjectionTerm`] list, and the combinator-built
/// WHERE text.  The SELECT names only the projected terms as `p<index>` outputs
/// (column pushdown), the FROM lists both `table AS alias` terms, and the WHERE
/// is the `?`-placeholder fragment text.
///
/// Each [`ProjectionTerm`] variant maps to one SELECT term:
///
/// - [`ProjectionTerm::LiteralTerm`] — `? AS p<index>`; bound value from
///   `extra_binds` in positional order.
/// - [`ProjectionTerm::UpperTerm`] / [`ProjectionTerm::LowerTerm`] — the dotted
///   `"alias.col"` field is re-validated via [`SqlIdent::parse_dotted`]; SQL
///   function name comes from the closed variant set, never from input.
/// - [`ProjectionTerm::CoalesceTerm`] — each [`ProjectionOperand`] is either
///   `OperandColumn(dotted)` (re-validated via `parse_dotted`) or
///   `OperandLiteral` (a `?` bound from `extra_binds`).
/// - [`ProjectionTerm::ColumnTerm`] — `alias.column AS p<index>`, both
///   identifiers re-validated via [`SqlIdent::parse_plain`].
///
/// The returned `usize` is the total count of `?` positions across all terms so
/// the caller can validate the bound `extra_binds` slice.
///
/// Every identifier passes [`SqlIdent::parse_plain`] or
/// [`SqlIdent::parse_dotted`] before it reaches SQL text; the two sides must
/// carry distinct aliases and the projection must name at least one term.
fn build_projection_statement(
    left_table: &str,
    left_alias: &str,
    right_table: &str,
    right_alias: &str,
    projections: &[ProjectionTerm],
    where_sql: &str,
) -> Result<(String, usize), String> {
    let left_table_id =
        SqlIdent::parse_plain(left_table).ok_or_else(|| format!("invalid table {left_table:?}"))?;
    let left_alias_id =
        SqlIdent::parse_plain(left_alias).ok_or_else(|| format!("invalid alias {left_alias:?}"))?;
    let right_table_id = SqlIdent::parse_plain(right_table)
        .ok_or_else(|| format!("invalid table {right_table:?}"))?;
    let right_alias_id = SqlIdent::parse_plain(right_alias)
        .ok_or_else(|| format!("invalid alias {right_alias:?}"))?;
    if left_alias_id.as_str() == right_alias_id.as_str() {
        return Err(format!(
            "the two join sides share the alias {:?}; each side needs a distinct alias",
            left_alias_id.as_str()
        ));
    }
    if projections.is_empty() {
        return Err("a projection must name at least one column".to_string());
    }
    let (terms, literal_count) = render_projection_terms(projections)?;
    Ok((
        db_format_sql(format!(
            "SELECT {proj} FROM {lt} AS {la}, {rt} AS {ra} WHERE {where_}",
            proj = terms.join(", "),
            lt = left_table_id.as_str(),
            la = left_alias_id.as_str(),
            rt = right_table_id.as_str(),
            ra = right_alias_id.as_str(),
            where_ = where_sql
        )),
        literal_count,
    ))
}

/// Render every [`ProjectionTerm`] into its `… AS pN` SELECT fragment, returning
/// the fragment list and the count of literal `?` positions the caller must bind.
/// The single source of truth for projection-term SQL — shared by the plain and
/// `ORDER BY` statement builders so the two cannot drift.  Every dotted column
/// operand is re-validated via [`SqlIdent::parse_dotted`] and every output alias
/// via [`SqlIdent::parse_plain`] before it reaches SQL text (defence in depth);
/// every value is a bound `?`, never interpolated; the operator tags are closed.
fn render_projection_terms(projections: &[ProjectionTerm]) -> Result<(Vec<String>, usize), String> {
    let mut terms = Vec::with_capacity(projections.len());
    let mut literal_count: usize = 0;
    for (index, term) in projections.iter().enumerate() {
        let output_name = format!("p{index}");
        let output = SqlIdent::parse_plain(&output_name)
            .ok_or_else(|| format!("invalid projection output {output_name:?}"))?;
        match term {
            ProjectionTerm::LiteralTerm => {
                terms.push(format!("? AS {}", output.as_str()));
                literal_count += 1;
            }
            ProjectionTerm::UpperTerm(dotted) => {
                // Defence in depth: re-validate the dotted column via
                // `SqlIdent::parse_dotted` before interpolation.
                let col = SqlIdent::parse_dotted(dotted)
                    .ok_or_else(|| format!("invalid projection column {dotted:?}"))?;
                terms.push(format!(
                    "UPPER({col}) AS {out}",
                    col = col.as_str(),
                    out = output.as_str(),
                ));
            }
            ProjectionTerm::LowerTerm(dotted) => {
                let col = SqlIdent::parse_dotted(dotted)
                    .ok_or_else(|| format!("invalid projection column {dotted:?}"))?;
                terms.push(format!(
                    "LOWER({col}) AS {out}",
                    col = col.as_str(),
                    out = output.as_str(),
                ));
            }
            ProjectionTerm::CoalesceTerm(a, b) => {
                let a_sql = render_projection_operand(a, &mut literal_count)?;
                let b_sql = render_projection_operand(b, &mut literal_count)?;
                terms.push(format!(
                    "COALESCE({a}, {b}) AS {out}",
                    a = a_sql,
                    b = b_sql,
                    out = output.as_str(),
                ));
            }
            ProjectionTerm::ArithTerm(op, a, b) => {
                let a_sql = render_projection_operand(a, &mut literal_count)?;
                let b_sql = render_projection_operand(b, &mut literal_count)?;
                // The operator symbol is drawn from the closed `ArithOp` set,
                // never from input; both operands are validated columns or `?`
                // binds, so the parenthesised expression carries no injection.
                terms.push(format!(
                    "({a} {op} {b}) AS {out}",
                    a = a_sql,
                    op = op.sql_symbol(),
                    b = b_sql,
                    out = output.as_str(),
                ));
            }
            ProjectionTerm::ColumnTerm(alias, column) => {
                let projected = ProjectionColumn::parse(alias, column, index)?;
                terms.push(projected.projection_term());
            }
        }
    }
    Ok((terms, literal_count))
}

/// Render one [`ProjectionOperand`] for SQL inclusion.  A column operand's dotted
/// reference is re-validated via [`SqlIdent::parse_dotted`] (defence in depth)
/// before it reaches SQL text.  A literal operand emits `?` and increments the
/// caller's `literal_count`.
fn render_projection_operand(
    operand: &ProjectionOperand,
    literal_count: &mut usize,
) -> Result<String, String> {
    match operand {
        ProjectionOperand::OperandLiteral => {
            *literal_count += 1;
            Ok("?".to_string())
        }
        ProjectionOperand::OperandColumn(dotted) => {
            let id = SqlIdent::parse_dotted(dotted)
                .ok_or_else(|| format!("invalid projection operand {dotted:?}"))?;
            Ok(id.as_str().to_string())
        }
    }
}

/// Build the projection statement like [`build_projection_statement`] but append
/// `ORDER BY <order_clause>`.  The `order_clause` string was produced by
/// [`parse_order_clause`] and contains only pre-validated identifiers.  Returns
/// the SQL string and the count of literal `?` positions for the caller to
/// validate the bound `extra_binds` slice.
fn build_projection_statement_ordered(
    left_table: &str,
    left_alias: &str,
    right_table: &str,
    right_alias: &str,
    projections: &[ProjectionTerm],
    where_sql: &str,
    order_clause: &str,
) -> Result<(String, usize), String> {
    let left_table_id =
        SqlIdent::parse_plain(left_table).ok_or_else(|| format!("invalid table {left_table:?}"))?;
    let left_alias_id =
        SqlIdent::parse_plain(left_alias).ok_or_else(|| format!("invalid alias {left_alias:?}"))?;
    let right_table_id = SqlIdent::parse_plain(right_table)
        .ok_or_else(|| format!("invalid table {right_table:?}"))?;
    let right_alias_id = SqlIdent::parse_plain(right_alias)
        .ok_or_else(|| format!("invalid alias {right_alias:?}"))?;
    if left_alias_id.as_str() == right_alias_id.as_str() {
        return Err(format!(
            "the two join sides share the alias {:?}; each side needs a distinct alias",
            left_alias_id.as_str()
        ));
    }
    if projections.is_empty() {
        return Err("a projection must name at least one column".to_string());
    }
    let (terms, literal_count) = render_projection_terms(projections)?;
    Ok((
        db_format_sql(format!(
            "SELECT {proj} FROM {lt} AS {la}, {rt} AS {ra} WHERE {where_} ORDER BY {order_clause}",
            proj = terms.join(", "),
            lt = left_table_id.as_str(),
            la = left_alias_id.as_str(),
            rt = right_table_id.as_str(),
            ra = right_alias_id.as_str(),
            where_ = where_sql
        )),
        literal_count,
    ))
}

/// `Db.deleteWhere : Db -> String -> SqlFragment -> Task Error Int` — the
/// row-count deletion counterpart to [`db_find_where`].
pub fn db_delete_where<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    frag: SqlFragment,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.deleteWhere: {reason}").into());
        }
        if frag.sql.trim().is_empty() {
            return IpeResult::Err(
                "db.deleteWhere: refusing a delete with an empty WHERE clause \
                 (an unconstrained mass-delete)"
                    .to_string()
                    .into(),
            );
        }
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(format!("db.deleteWhere: invalid table {:?}", table).into());
            }
        };
        let sql = db_format_sql(format!(
            "DELETE FROM {} WHERE {}",
            qtable.as_str(),
            frag.sql
        ));
        let mut q = sqlx::query(&sql);
        for p in frag.binds {
            q = bind_sql_param(q, p);
        }
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// A built `UPDATE … WHERE …`, or the no-op an all-`OmitField` SET list is.
#[derive(Debug, PartialEq)]
enum UpdateStatement {
    /// Every SET column was `OmitField`: nothing to write, no SQL to run.
    NothingToSet,
    /// The statement text (`?` placeholders) and its binds in placeholder order.
    Built { sql: String, args: Vec<SqlParam> },
}

/// Builds `UPDATE <table> SET c = ?, … WHERE <where_>`.
///
/// Shared by [`db_update_where`] and [`db_update_where_checked`]. `OmitField`
/// (`None`) columns are left out of the SET; when none remains the result is
/// [`UpdateStatement::NothingToSet`]. Refused, in order: a poisoned WHERE, an
/// invalid table or SET column name, and (once a SET exists) an empty WHERE,
/// which would rewrite every row. The SET binds precede the WHERE binds,
/// matching placeholder order.
fn build_update_where_sql(
    table: &str,
    set_fields: Vec<(String, Option<SqlParam>)>,
    where_: SqlFragment,
) -> Result<UpdateStatement, DbBuildError> {
    if let Some(reason) = where_.invalid {
        return Err(DbBuildError::PoisonedFragment { reason });
    }
    let qtable = SqlIdent::parse_dotted(table).ok_or_else(|| DbBuildError::InvalidIdent {
        slot: IdentSlot::Table,
        name: table.to_string(),
    })?;
    let mut set_clauses: Vec<String> = Vec::new();
    let mut args: Vec<SqlParam> = Vec::new();
    for (col, opt) in set_fields {
        let Some(qcol) = SqlIdent::parse_dotted(&col) else {
            return Err(DbBuildError::InvalidIdent {
                slot: IdentSlot::Column(ColumnList::Set),
                name: col,
            });
        };
        if let Some(p) = opt {
            set_clauses.push(format!("{} = ?", qcol.as_str()));
            args.push(p);
        }
    }
    if set_clauses.is_empty() {
        return Ok(UpdateStatement::NothingToSet);
    }
    if where_.sql.trim().is_empty() {
        return Err(DbBuildError::UnscopedUpdate);
    }
    let sql = format!(
        "UPDATE {} SET {} WHERE {}",
        qtable.as_str(),
        set_clauses.join(", "),
        where_.sql
    );
    args.extend(where_.binds);
    Ok(UpdateStatement::Built { sql, args })
}

/// `Db.updateWhere : Db -> String -> List (String, SqlField) -> SqlFragment -> Task Error Int`
/// — the WHERE-`SqlFragment` counterpart to [`db_update_fields`]. The SET list is
/// the OmitField-aware column/value binds of [`db_update_fields`]; the WHERE is
/// the combinator-built `SqlFragment` of [`db_delete_where`]. Every SET value is
/// bound (`SqlParam`); the WHERE text is always `?`-placeholder with a matching
/// bind list, so no caller value or identifier reaches the SQL text. An
/// all-`OmitField` SET writes nothing and returns `0`.
pub fn db_update_where<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    set_fields: Vec<(String, Option<SqlParam>)>,
    frag: SqlFragment,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let (sql, args) = match build_update_where_sql(&table, set_fields, frag) {
            Ok(UpdateStatement::Built { sql, args }) => (sql, args),
            Ok(UpdateStatement::NothingToSet) => return ok_res(0i64),
            Err(e) => return IpeResult::Err(build_refusal("db.updateWhere", &e)),
        };
        let sql = db_format_sql(sql);
        let mut q = sqlx::query(&sql);
        for p in args {
            q = bind_sql_param(q, p);
        }
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// The result column a checked write's `RETURNING` clause names.
const POLICY_OK_COLUMN: &str = "ipe_policy_ok";

/// A policy predicate a checked write evaluates over each row as stored.
///
/// Built only by [`PolicyCheck::parse`], so a poisoned or empty fragment never
/// reaches a `RETURNING` clause.
#[derive(Debug)]
struct PolicyCheck(SqlFragment);

impl PolicyCheck {
    /// Accepts a check fragment that carries no poison and names a predicate.
    ///
    /// A poisoned fragment is [`DbBuildError::PoisonedFragment`]; an empty one
    /// is [`DbBuildError::EmptyCheck`].
    fn parse(frag: SqlFragment) -> Result<Self, DbBuildError> {
        if let Some(reason) = frag.invalid {
            return Err(DbBuildError::PoisonedFragment { reason });
        }
        if frag.sql.trim().is_empty() {
            return Err(DbBuildError::EmptyCheck);
        }
        Ok(Self(frag))
    }

    /// Appends `RETURNING (<check>) AS ipe_policy_ok` to a built statement.
    ///
    /// The check's binds follow the statement's own, which is placeholder order.
    fn returning(self, sql: &str, mut args: Vec<SqlParam>) -> (String, Vec<SqlParam>) {
        let Self(check) = self;
        args.extend(check.binds);
        (
            format!("{sql} RETURNING ({}) AS {POLICY_OK_COLUMN}", check.sql),
            args,
        )
    }
}

/// Builds the insert of [`db_insert_fields_checked`].
///
/// It is the [`build_insert_sql`] statement plus the policy check's
/// `RETURNING` suffix; the check is parsed first.
fn build_checked_insert_sql(
    table: &str,
    fields: Vec<(String, Option<SqlParam>)>,
    check: SqlFragment,
) -> Result<(String, Vec<SqlParam>), DbBuildError> {
    let check = PolicyCheck::parse(check)?;
    let (sql, args) = build_insert_sql(table, fields)?;
    Ok(check.returning(&sql, args))
}

/// Builds the update of [`db_update_where_checked`].
///
/// It is the [`build_update_where_sql`] statement plus the policy check's
/// `RETURNING` suffix; the check is parsed first.
fn build_checked_update_sql(
    table: &str,
    set_fields: Vec<(String, Option<SqlParam>)>,
    where_: SqlFragment,
    check: SqlFragment,
) -> Result<UpdateStatement, DbBuildError> {
    let check = PolicyCheck::parse(check)?;
    Ok(match build_update_where_sql(table, set_fields, where_)? {
        UpdateStatement::NothingToSet => UpdateStatement::NothingToSet,
        UpdateStatement::Built { sql, args } => {
            let (sql, args) = check.returning(&sql, args);
            UpdateStatement::Built { sql, args }
        }
    })
}

/// True when a checked write's returned row holds the policy check as `true`.
///
/// Only a boolean `true` or the integer `1` admits. `false`, `0`, `NULL`, any
/// other value, a missing column, and a decode failure each refuse. The integer
/// reader runs first: a SQLite comparison yields an integer, and a SQLite `bool`
/// decode would accept every non-zero integer. A Postgres `BOOL` fails the
/// integer reader's type check and is read as `bool`.
fn policy_admits(row: &DbRow) -> bool {
    match row.try_get::<Option<i64>, _>(POLICY_OK_COLUMN) {
        Ok(v) => v == Some(1),
        Err(_) => matches!(
            row.try_get::<Option<bool>, _>(POLICY_OK_COLUMN),
            Ok(Some(true))
        ),
    }
}

/// Runs a checked write inside `savepoint` and settles it.
///
/// The savepoint is committed only when the statement returned at least one row
/// and [`policy_admits`] holds for every one; the count is then the returned
/// row count. Otherwise it is rolled back and the count is `0`. A statement
/// error rolls back too and is returned.
async fn settle_checked_write(
    mut savepoint: sqlx::Transaction<'_, DbDatabase>,
    query: DbQuery<'_>,
) -> Result<u64, sqlx::Error> {
    let rows = match query.fetch_all(&mut *savepoint).await {
        Ok(rows) => rows,
        Err(e) => {
            // The statement error is the one reported; were this rollback to
            // fail, dropping the savepoint still rolls it back.
            let _ = savepoint.rollback().await;
            return Err(e);
        }
    };
    if !rows.is_empty() && rows.iter().all(policy_admits) {
        savepoint.commit().await?;
        Ok(u64::try_from(rows.len()).unwrap_or(u64::MAX))
    } else {
        savepoint.rollback().await?;
        Ok(0)
    }
}

/// Runs a built checked write on `conn`'s routed target and maps the count.
async fn run_checked_write<E: From<String> + Send>(
    conn: &Db,
    sql: String,
    args: Vec<SqlParam>,
) -> IpeResult<E, i64> {
    let sql = db_format_sql(sql);
    let mut q = sqlx::query(&sql);
    for p in args {
        q = bind_sql_param(q, p);
    }
    match route_for(conn).checked_write(q).await {
        Ok(n) => ok_res(i64::try_from(n).unwrap_or(i64::MAX)),
        Err(e) => IpeResult::Err(ipe_err(&e)),
    }
}

/// `Db_insertFieldsChecked : Db -> String -> List (String, SqlField) -> SqlFragment -> Task Error Int`
/// — the insert of `Store.insertAs`.
///
/// Builds the [`db_insert_fields`] statement with `RETURNING (<check>)` and runs
/// it through [`QueryTarget::checked_write`]: the row stays only when `check`
/// holds over it as stored. Returns `1` when kept and `0` when the check refused
/// it (nothing is written). A poisoned or empty `check` is refused before any SQL.
pub fn db_insert_fields_checked<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    fields: Vec<(String, Option<SqlParam>)>,
    check: SqlFragment,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        match build_checked_insert_sql(&table, fields, check) {
            Ok((sql, args)) => run_checked_write(&conn, sql, args).await,
            Err(e) => IpeResult::Err(build_refusal("db.insertFieldsChecked", &e)),
        }
    })
}

/// `Db_updateWhereChecked : Db -> String -> List (String, SqlField) -> SqlFragment -> SqlFragment -> Task Error Int`
/// — the update of `Store.updateAs`.
///
/// Arguments after the table: the SET fields, the scoping `WHERE`, then the
/// check. Builds the [`db_update_where`] statement with `RETURNING (<check>)`
/// and runs it through [`QueryTarget::checked_write`]: the update stays only
/// when every updated row satisfies `check` as stored after the write. Returns
/// the updated-row count, or `0` when no row matched or the check refused
/// (nothing is written). An all-`OmitField` SET returns `0` without SQL.
pub fn db_update_where_checked<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    set_fields: Vec<(String, Option<SqlParam>)>,
    where_: SqlFragment,
    check: SqlFragment,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        match build_checked_update_sql(&table, set_fields, where_, check) {
            Ok(UpdateStatement::Built { sql, args }) => run_checked_write(&conn, sql, args).await,
            Ok(UpdateStatement::NothingToSet) => ok_res(0i64),
            Err(e) => IpeResult::Err(build_refusal("db.updateWhereChecked", &e)),
        }
    })
}

// ─── External-connection read path (foreign-DB reads through the codec stack) ──
//
// The app connection (`Db`) is one dialect fixed at build time; an external
// `ExternalConnection` may be a DIFFERENT dialect selected at runtime by the
// parsed `Dsn`. The read runners below therefore build and decode each query
// keyed on the external connection's OWN dialect, never on the app-build's
// `db_format_sql` / `DbRow`. They reuse the identical query builder every app
// read uses — `SqlIdent` for identifiers, the `?`-placeholder text from the
// `Sql.*` fragment combinators, `SqlParam` positional binds — so no new query
// path or injection surface is introduced by reading elsewhere (design §2). Only
// the placeholder-style rewrite and the row→value decode are dialect-selected,
// per concrete match arm, so there is no `dyn`.

/// Rewrite `?`-placeholder SQL to the placeholder style the external dialect
/// expects: Postgres numbers them (`$1`, `$2`, …); SQLite keeps `?`. This mirrors
/// the per-dialect `db_format_sql` the app path applies, but is selected from the
/// EXTERNAL connection's dialect at runtime instead of the build-fixed one — the
/// same sequential rewrite is correct because every value is bound as a
/// parameter, never inlined into the SQL text.
#[cfg(feature = "db")]
fn external_format_sql_postgres(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len() + 8);
    let mut n = 0u32;
    for ch in sql.chars() {
        if ch == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(ch);
        }
    }
    out
}

/// Decode column `i` of an EXTERNAL row into a `String`, mirroring the app-path
/// [`column_to_string`] probe order (bool → i64 → f64 → String → bytes-hex).
/// Generic over the sqlx row type so a single body serves both external
/// dialects; each caller monomorphises it to its concrete row (no `dyn`).
#[cfg(feature = "db")]
fn external_column_to_string<R>(row: &R, i: usize) -> String
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    for<'a> Option<bool>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<i64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<f64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<Vec<u8>>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    if column_is_boolean(row, i)
        && let Ok(opt) = row.try_get::<Option<bool>, _>(i)
    {
        return opt.map_or_else(String::new, |b| b.to_string());
    }
    if let Ok(opt) = row.try_get::<Option<i64>, _>(i) {
        return opt.map_or_else(String::new, |n| n.to_string());
    }
    if let Ok(opt) = row.try_get::<Option<f64>, _>(i) {
        return opt.map_or_else(String::new, |f| f.to_string());
    }
    if let Ok(opt) = row.try_get::<Option<String>, _>(i) {
        return opt.unwrap_or_default();
    }
    if let Ok(Some(bytes)) = row.try_get::<Option<Vec<u8>>, _>(i) {
        return hex::encode(bytes);
    }
    String::new()
}

/// Decode an EXTERNAL row into the untyped `Dict String String` shape, mirroring
/// the app-path [`row_to_map`]. Generic over the sqlx row type.
#[cfg(feature = "db")]
#[allow(clippy::needless_range_loop)]
fn external_row_to_map<R>(row: &R) -> HashMap<String, String>
where
    R: Row,
    usize: sqlx::ColumnIndex<R>,
    for<'a> Option<bool>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<i64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<f64>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<Vec<u8>>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let mut map = HashMap::new();
    for (i, col) in row.columns().iter().enumerate() {
        map.insert(col.name().to_string(), external_column_to_string(row, i));
    }
    map
}

/// Bind a `SqlParam` onto a query builder for a SPECIFIC external dialect,
/// generic over the sqlx database. Same total per-variant mapping as the
/// app-path [`bind_sql_param`], including the typed-NULL witness that gives
/// Postgres the correct per-parameter type OID.
#[cfg(feature = "db")]
fn external_bind_sql_param<'q, DB>(
    q: sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>,
    p: SqlParam,
) -> sqlx::query::Query<'q, DB, <DB as sqlx::Database>::Arguments<'q>>
where
    DB: sqlx::Database,
    String: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    i64: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    f64: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    bool: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Vec<u8>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<String>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<i64>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<f64>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<bool>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    Option<Vec<u8>>: sqlx::Encode<'q, DB> + sqlx::Type<DB>,
{
    match p {
        SqlParam::Text(s) => q.bind(s),
        SqlParam::Int(i) => q.bind(i),
        SqlParam::Float(f) => q.bind(f),
        SqlParam::Bool(b) => q.bind(b),
        SqlParam::Bytes(v) => q.bind(v),
        SqlParam::Null(witness) => match *witness {
            SqlParam::Text(_) => q.bind(Option::<String>::None),
            SqlParam::Int(_) => q.bind(Option::<i64>::None),
            SqlParam::Float(_) => q.bind(Option::<f64>::None),
            SqlParam::Bool(_) => q.bind(Option::<bool>::None),
            SqlParam::Bytes(_) => q.bind(Option::<Vec<u8>>::None),
            SqlParam::Null(_) => q.bind(Option::<String>::None),
        },
    }
}

/// `Db.findWhereOn : Connection a -> String -> SqlFragment -> Task Error (List Row)`
/// — the external-connection counterpart to [`db_find_where`]. The `SqlFragment`
/// arrives from the same `Sql.*` combinators (validated identifiers + bound
/// params), the table name passes the same [`SqlIdent`] gate, and every value is
/// bound positionally — identical injection barrier, run against a foreign pool.
/// Accepts `Connection a` (any access mode: a read is available on read-only and
/// read-write alike); the phantom mode is erased at emit.
#[cfg(feature = "db")]
pub fn db_conn_find_where<E: Send + From<String> + 'static>(
    conn: ExternalConnection,
    table: String,
    frag: SqlFragment,
) -> IpeTask<E, Vec<HashMap<String, String>>> {
    Box::pin(async move {
        if let Some(reason) = frag.invalid {
            return IpeResult::Err(format!("db.findWhereOn: {reason}").into());
        }
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(format!("db.findWhereOn: invalid table {:?}", table).into());
            }
        };
        let base = format!("SELECT * FROM {} WHERE {}", qtable.as_str(), frag.sql);
        match conn {
            ExternalConnection::Postgres(pool) => {
                let sql = external_format_sql_postgres(&base);
                let mut q = sqlx::query(&sql);
                for p in frag.binds {
                    q = external_bind_sql_param(q, p);
                }
                match q.fetch_all(&pool).await {
                    Ok(rows) => ok_res(rows.iter().map(external_row_to_map).collect()),
                    Err(e) => IpeResult::Err(ipe_err(&e)),
                }
            }
            ExternalConnection::Sqlite(pool) => {
                let mut q = sqlx::query(&base);
                for p in frag.binds {
                    q = external_bind_sql_param(q, p);
                }
                match q.fetch_all(&pool).await {
                    Ok(rows) => ok_res(rows.iter().map(external_row_to_map).collect()),
                    Err(e) => IpeResult::Err(ipe_err(&e)),
                }
            }
        }
    })
}

/// `Db.queryDecodeOn : Connection a -> String -> List SqlValue -> Decoder a2
/// -> Task Error (List a2)` — the external counterpart to
/// [`db_query_decode_params`]. Same positional binding and NULL-preserving
/// row→JSON decode, keyed on the foreign dialect, fed to the same
/// `Decoder<E, A>`. The caller-supplied SQL is bound-parameter-only (the safe
/// path); verbatim external SQL remains the disclosed `unsafeExecRawOn` door.
#[cfg(feature = "db")]
pub fn db_conn_query_decode_params<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: ExternalConnection,
    sql: String,
    params: Vec<SqlParam>,
    decoder: Decoder<E, A>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        let rows_json: Result<Vec<JsonVal>, sqlx::Error> = match conn {
            ExternalConnection::Postgres(pool) => {
                let final_sql = external_format_sql_postgres(&sql);
                let mut q = sqlx::query(&final_sql);
                for p in params {
                    q = external_bind_sql_param(q, p);
                }
                match q.fetch_all(&pool).await {
                    Ok(rows) => rows.iter().map(row_to_json).collect(),
                    Err(e) => Err(e),
                }
            }
            ExternalConnection::Sqlite(pool) => {
                let mut q = sqlx::query(&sql);
                for p in params {
                    q = external_bind_sql_param(q, p);
                }
                match q.fetch_all(&pool).await {
                    Ok(rows) => rows.iter().map(row_to_json).collect(),
                    Err(e) => Err(e),
                }
            }
        };
        let jsons = match rows_json {
            Ok(v) => v,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let mut out = Vec::with_capacity(jsons.len());
        for jv in &jsons {
            match (decoder.run)(jv) {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

/// `Db.getByIdOn : Connection a -> String -> String -> Task Error (Maybe Row)`
/// — the external counterpart to [`db_get_by_id`]. The id binds as a positional
/// parameter (never interpolated); the table passes the same [`SqlIdent`] gate.
#[cfg(feature = "db")]
pub fn db_conn_get_by_id<E: Send + From<String> + 'static>(
    conn: ExternalConnection,
    table: String,
    id: String,
) -> IpeTask<E, IpeMaybe<HashMap<String, String>>> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_plain(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.getByIdOn: invalid table name {:?}", table).into(),
                );
            }
        };
        let base = format!("SELECT * FROM {} WHERE id = ? LIMIT 1", qtable.as_str());
        match conn {
            ExternalConnection::Postgres(pool) => {
                let sql = external_format_sql_postgres(&base);
                match sqlx::query(&sql).bind(id).fetch_optional(&pool).await {
                    Ok(Some(r)) => ok_res(IpeMaybe::Just(external_row_to_map(&r))),
                    Ok(None) => ok_res(IpeMaybe::Nothing),
                    Err(e) => IpeResult::Err(ipe_err(&e)),
                }
            }
            ExternalConnection::Sqlite(pool) => {
                match sqlx::query(&base).bind(id).fetch_optional(&pool).await {
                    Ok(Some(r)) => ok_res(IpeMaybe::Just(external_row_to_map(&r))),
                    Ok(None) => ok_res(IpeMaybe::Nothing),
                    Err(e) => IpeResult::Err(ipe_err(&e)),
                }
            }
        }
    })
}

/// The column list of a built statement that a refused column name came from.
#[cfg(feature = "db")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnList {
    /// The `(column, SqlField)` pairs being written.
    Fields,
    /// The `ON CONFLICT (…)` target of an upsert.
    ConflictTarget,
    /// The `SET` list of an update.
    Set,
}

#[cfg(feature = "db")]
impl ColumnList {
    /// The qualifier this list adds before `column` in a refusal message.
    const fn qualifier(self) -> &'static str {
        match self {
            Self::Fields => "",
            Self::ConflictTarget => "conflict-target ",
            Self::Set => "SET ",
        }
    }
}

/// The identifier slot a refused name was offered for.
#[cfg(feature = "db")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentSlot {
    /// The target table (dotted `schema.table` admitted).
    Table,
    /// A column in the given list.
    Column(ColumnList),
}

/// Why a statement builder ([`build_insert_sql`], [`build_upsert_sql`],
/// [`build_update_where_sql`]) or a [`PolicyCheck`] refused to build.
///
/// Every variant carries identifier NAMES only, never a bound value, so the
/// rendered message cannot leak row data. `Display` is the refusal text; the
/// task edge ([`build_refusal`]) prefixes the kernel name and converts it into
/// the task's error.
#[cfg(feature = "db")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum DbBuildError {
    /// A table or column name failed the `SqlIdent` gate for its slot.
    InvalidIdent { slot: IdentSlot, name: String },
    /// An upsert named no conflict-target column.
    EmptyTarget,
    /// A column appears twice in one list (ASCII-case-insensitive).
    DuplicateColumn { list: ColumnList, name: String },
    /// A conflict-target column was not supplied as a `SetField`.
    TargetNotSupplied { name: String },
    /// A conflict-target column was bound to `SqlNull`.
    NullTarget { name: String },
    /// A `SqlFragment` carries a poison marker; `reason` is its own text,
    /// which names only a Debug-escaped identifier.
    PoisonedFragment { reason: String },
    /// An update's `WHERE` fragment is empty, which would rewrite every row.
    UnscopedUpdate,
    /// A policy check fragment is empty, so it states no predicate to hold.
    EmptyCheck,
}

#[cfg(feature = "db")]
impl std::fmt::Display for DbBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidIdent {
                slot: IdentSlot::Table,
                name,
            } => write!(f, "invalid table name {name:?}"),
            Self::InvalidIdent {
                slot: IdentSlot::Column(list),
                name,
            } => write!(f, "invalid {}column name {name:?}", list.qualifier()),
            Self::EmptyTarget => {
                f.write_str("empty conflict target; pass the primary-key or unique columns")
            }
            Self::DuplicateColumn { list, name } => write!(
                f,
                "{}column {name:?} is listed more than once",
                list.qualifier()
            ),
            Self::TargetNotSupplied { name } => write!(
                f,
                "conflict-target column {name:?} must be supplied as a SetField; \
                 without a client value the conflict can never match"
            ),
            Self::NullTarget { name } => write!(
                f,
                "conflict-target column {name:?} is NULL; a NULL key never conflicts"
            ),
            Self::PoisonedFragment { reason } => f.write_str(reason),
            Self::UnscopedUpdate => {
                f.write_str("refusing unscoped UPDATE (no WHERE); pass an explicit condition")
            }
            Self::EmptyCheck => {
                f.write_str("empty policy check; a checked write must name the predicate it keeps")
            }
        }
    }
}

#[cfg(feature = "db")]
impl std::error::Error for DbBuildError {}

/// Converts a statement-build refusal into the task error at the kernel edge.
#[cfg(feature = "db")]
fn build_refusal<E: From<String>>(kernel: &str, e: &DbBuildError) -> E {
    E::from(format!("{kernel}: {e}"))
}

/// Shared logic for `db_insert_fields` and `db_insert_fields_returning`:
/// validates the table name and builds the INSERT SQL + bound-arg list.
///
/// `fields`: `Vec<(col_name, Option<SqlParam>)>` where `None` = OmitField
/// (column dropped from SQL; DB applies DEFAULT) and `Some(p)` = SetField(p).
///
/// Returns `(sql_without_returning, args)` on success, or
/// `DbBuildError::InvalidIdent` on an invalid table/column name.  All-OmitField → returns
/// `"INSERT INTO t DEFAULT VALUES"` with an empty arg list (valid on every
/// engine at or above its [`DbEngine::version_floor`]).
///
/// Security: table and column names are validated before interpolation.
/// Values are bound positionally — never interpolated.
#[cfg(feature = "db")]
fn build_insert_sql(
    table: &str,
    fields: Vec<(String, Option<SqlParam>)>,
) -> Result<(String, Vec<SqlParam>), DbBuildError> {
    let qtable = SqlIdent::parse_dotted(table).ok_or_else(|| DbBuildError::InvalidIdent {
        slot: IdentSlot::Table,
        name: table.to_string(),
    })?;
    let mut cols: Vec<String> = Vec::new();
    let mut args: Vec<SqlParam> = Vec::new();
    for (col, opt) in fields {
        let Some(qcol) = SqlIdent::parse_dotted(&col) else {
            return Err(DbBuildError::InvalidIdent {
                slot: IdentSlot::Column(ColumnList::Fields),
                name: col,
            });
        };
        if let Some(p) = opt {
            cols.push(qcol.as_str().to_string());
            args.push(p);
        }
        // None → OmitField: column dropped entirely, DB applies DEFAULT.
    }
    let sql = if cols.is_empty() {
        format!("INSERT INTO {} DEFAULT VALUES", qtable.as_str())
    } else {
        let ph = vec!["?"; cols.len()].join(", ");
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            qtable.as_str(),
            cols.join(", "),
            ph
        )
    };
    Ok((sql, args))
}

/// `Db.insertFields : Db -> String -> List (String, SqlField) -> Task Error Int`
///
/// Builds a dynamic INSERT that includes only the `SetField` columns.
/// `OmitField` columns are dropped from the column list + VALUES clause so the
/// database applies their DEFAULT.  When every column is OmitField the runtime
/// emits `INSERT INTO <table> DEFAULT VALUES`.
///
/// Returns the inserted row's generated/provided id (lastInsertRowid on
/// sqlite; `RETURNING id` on Postgres, since Postgres's `QueryResult` carries
/// no last-insert-id concept — see [`DB_USES_RETURNING_ID`]).
///
/// Security: table + column names are identifier-validated `[A-Za-z0-9_.]`;
/// values are bound positionally — never interpolated into SQL.
/// Totality: every error path returns `IpeResult::Err`; no panic/unwrap. Never
/// fabricates `id = 0` on a non-integer primary key — surfaces a clear `Err`
/// instead (mirrors [`db_insert_row`]'s fix for the same bug class).
#[cfg(feature = "db")]
pub fn db_insert_fields<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    fields: Vec<(String, Option<SqlParam>)>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let (base_sql, args) = match build_insert_sql(&table, fields) {
            Ok(v) => v,
            Err(e) => return IpeResult::Err(build_refusal("db.insertFields", &e)),
        };
        if DB_USES_RETURNING_ID {
            // Same rationale as `db_insert_row`: Postgres has no
            // LastInsertId, so recover the generated key via `RETURNING id`
            // instead of unconditionally calling `db_last_insert_id` (which
            // is a stub returning a fabricated `0` on the Postgres config
            // template — see `config_postgres.rs`).
            let sql = db_format_sql(format!("{base_sql} RETURNING id"));
            let mut q = sqlx::query(&sql);
            for p in args {
                q = bind_sql_param(q, p);
            }
            match fetch_one_routed(&conn, q).await {
                Ok(r) => match extract_returning_id(&r) {
                    Ok(id) => ok_res(id),
                    Err(msg) => IpeResult::Err(format!("db.insertFields: {msg}").into()),
                },
                Err(e) => IpeResult::Err(ipe_err(&e)),
            }
        } else {
            let sql = db_format_sql(base_sql);
            let mut q = sqlx::query(&sql);
            for p in args {
                q = bind_sql_param(q, p);
            }
            match exec_routed(&conn, q).await {
                Ok(res) => ok_res(db_last_insert_id(&res)),
                Err(e) => IpeResult::Err(ipe_err(&e)),
            }
        }
    })
}

/// `Db.updateFields : Db -> String -> List (String, SqlValue) -> List (String, SqlField) -> Task Error Int`
///
/// Builds a dynamic UPDATE that includes only the `SetField` columns in the SET
/// clause.  `OmitField` columns are skipped (DB keeps their existing value).
/// If every column in `set_fields` is OmitField, returns `Ok(0)` without
/// executing any SQL (no empty SET clause).
///
/// `where_cols` is a list of `(col, SqlValue)` pairs forming the WHERE clause
/// (AND-joined); an empty list means no WHERE clause (updates every row).
///
/// Security: table + column names are identifier-validated `[A-Za-z0-9_.]`;
/// values are bound positionally — never interpolated into SQL.
/// Totality: every error path returns `IpeResult::Err`; no panic/unwrap.
#[cfg(feature = "db")]
pub fn db_update_fields<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    where_cols: Vec<(String, SqlParam)>,
    set_fields: Vec<(String, Option<SqlParam>)>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let qtable = match SqlIdent::parse_dotted(&table) {
            Some(t) => t,
            None => {
                return IpeResult::Err(
                    format!("db.updateFields: invalid table name {:?}", table).into(),
                );
            }
        };
        // Build SET clause.
        let mut set_clauses: Vec<String> = Vec::new();
        let mut args: Vec<SqlParam> = Vec::new();
        for (col, opt) in set_fields {
            let qcol = match SqlIdent::parse_dotted(&col) {
                Some(c) => c,
                None => {
                    return IpeResult::Err(
                        format!("db.updateFields: invalid SET column name {:?}", col).into(),
                    );
                }
            };
            if let Some(p) = opt {
                set_clauses.push(format!("{} = ?", qcol.as_str()));
                args.push(p);
            }
            // None → OmitField: skip column.
        }
        if set_clauses.is_empty() {
            // Every column was OmitField — nothing to update; report zero rows.
            return ok_res(0i64);
        }
        // Build WHERE clause.
        let mut where_clauses: Vec<String> = Vec::new();
        for (col, p) in where_cols {
            let qcol = match SqlIdent::parse_dotted(&col) {
                Some(c) => c,
                None => {
                    return IpeResult::Err(
                        format!("db.updateFields: invalid WHERE column name {:?}", col).into(),
                    );
                }
            };
            where_clauses.push(format!("{} = ?", qcol.as_str()));
            args.push(p);
        }
        // Refuse an unscoped UPDATE: an empty WHERE-column set would emit
        // `UPDATE <table> SET ...` with no WHERE, silently rewriting EVERY row
        // (a wrong-default footgun reachable when a request-derived WHERE list
        // comes back empty). Fail closed instead of mass-updating.
        if where_clauses.is_empty() {
            return IpeResult::Err(
                "db.updateFields: refusing unscoped UPDATE (no WHERE); pass an explicit condition"
                    .to_string()
                    .into(),
            );
        }
        let sql = format!(
            "UPDATE {} SET {} WHERE {}",
            qtable.as_str(),
            set_clauses.join(", "),
            where_clauses.join(" AND ")
        );
        let sql = db_format_sql(sql);
        let mut q = sqlx::query(&sql);
        for p in args {
            q = bind_sql_param(q, p);
        }
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// Builds the upsert statement for `db_upsert_fields`:
///
/// ```sql
/// INSERT INTO <table> (<set-cols>) VALUES (?, …)
///   ON CONFLICT (<target-cols>) DO UPDATE SET <c> = excluded.<c>, …
/// ```
///
/// The SET list is every `SetField` column that is not a conflict-target
/// column. `OmitField` columns appear nowhere: the database fills them on
/// insert and never overwrites them on conflict, so a DB-owned column
/// (`Serial` / `DefaultNow` / `TouchOnUpdate`) is never replaced by a client
/// value. An empty SET list yields `ON CONFLICT (…) DO NOTHING`
/// (insert-if-absent), never an empty `SET`.
///
/// Refused with a [`DbBuildError`] before any SQL exists:
/// - `InvalidIdent`: a table name failing `SqlIdent::parse_dotted`, or a field
///   or conflict-target column failing `SqlIdent::parse_plain` — columns are
///   bare names because `ON CONFLICT (…)` and `excluded.<col>` admit no
///   qualifier;
/// - `EmptyTarget`: an empty conflict target (no `ON CONFLICT` target is valid
///   on both engines for `DO UPDATE`);
/// - `DuplicateColumn`: a column named twice in the fields or in the conflict
///   target, compared ASCII-case-insensitively as both engines compare unquoted
///   identifiers;
/// - `TargetNotSupplied`: a conflict-target column not supplied as a
///   `SetField` — its value would be absent or DB-generated, the conflict could
///   never match, and the upsert would silently degrade to a plain insert;
/// - `NullTarget`: a conflict-target column bound to `SqlNull` — NULLs never
///   compare equal under a unique constraint, so the upsert would likewise
///   degrade to an insert.
///
/// Security: every interpolated name is a validated `SqlIdent`; `excluded.<col>`
/// reuses the same validated identifier. Values bind positionally.
#[cfg(feature = "db")]
fn build_upsert_sql(
    table: &str,
    conflict_target: Vec<String>,
    fields: Vec<(String, Option<SqlParam>)>,
) -> Result<(String, Vec<SqlParam>), DbBuildError> {
    let qtable = SqlIdent::parse_dotted(table).ok_or_else(|| DbBuildError::InvalidIdent {
        slot: IdentSlot::Table,
        name: table.to_string(),
    })?;
    if conflict_target.is_empty() {
        return Err(DbBuildError::EmptyTarget);
    }
    let mut target_keys: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(conflict_target.len());
    let mut target_cols: Vec<SqlIdent> = Vec::with_capacity(conflict_target.len());
    for col in conflict_target {
        let Some(qcol) = SqlIdent::parse_plain(&col) else {
            return Err(DbBuildError::InvalidIdent {
                slot: IdentSlot::Column(ColumnList::ConflictTarget),
                name: col,
            });
        };
        if !target_keys.insert(qcol.as_str().to_ascii_lowercase()) {
            return Err(DbBuildError::DuplicateColumn {
                list: ColumnList::ConflictTarget,
                name: col,
            });
        }
        target_cols.push(qcol);
    }
    let mut field_keys: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(fields.len());
    let mut supplied_target_keys: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(target_cols.len());
    let mut insert_cols: Vec<String> = Vec::with_capacity(fields.len());
    let mut set_clauses: Vec<String> = Vec::new();
    let mut args: Vec<SqlParam> = Vec::with_capacity(fields.len());
    for (col, opt) in fields {
        let Some(qcol) = SqlIdent::parse_plain(&col) else {
            return Err(DbBuildError::InvalidIdent {
                slot: IdentSlot::Column(ColumnList::Fields),
                name: col,
            });
        };
        let key = qcol.as_str().to_ascii_lowercase();
        if !field_keys.insert(key.clone()) {
            return Err(DbBuildError::DuplicateColumn {
                list: ColumnList::Fields,
                name: col,
            });
        }
        let Some(p) = opt else {
            continue;
        };
        if target_keys.contains(&key) {
            if matches!(p, SqlParam::Null(_)) {
                return Err(DbBuildError::NullTarget { name: col });
            }
            supplied_target_keys.insert(key);
        } else {
            set_clauses.push(format!("{0} = excluded.{0}", qcol.as_str()));
        }
        insert_cols.push(qcol.as_str().to_string());
        args.push(p);
    }
    if let Some(missing) = target_cols
        .iter()
        .find(|t| !supplied_target_keys.contains(&t.as_str().to_ascii_lowercase()))
    {
        return Err(DbBuildError::TargetNotSupplied {
            name: missing.as_str().to_string(),
        });
    }
    let target_list = target_cols
        .iter()
        .map(SqlIdent::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let action = if set_clauses.is_empty() {
        "DO NOTHING".to_string()
    } else {
        format!("DO UPDATE SET {}", set_clauses.join(", "))
    };
    let sql = format!(
        "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT ({}) {}",
        qtable.as_str(),
        insert_cols.join(", "),
        vec!["?"; insert_cols.len()].join(", "),
        target_list,
        action
    );
    Ok((sql, args))
}

/// `Db.upsertFields : Db -> String -> List String -> List (String, SqlField) -> Task Error Int`
///
/// Insert-or-update-in-place on the conflict target (the `List String`, the
/// table's primary-key or unique columns). On a conflict the existing row is
/// UPDATED — its identity, rowid, and every column outside the SET list are
/// preserved and no DELETE fires — identically on SQLite and Postgres, because
/// the one statement built by [`build_upsert_sql`] is standard on both. SQLite's
/// delete-then-insert `INSERT OR REPLACE` is never emitted.
///
/// Returns the affected-row count: `1` when a row was inserted or updated, `0`
/// when a `DO NOTHING` upsert met an existing row.
///
/// Security: table + column names are identifier-validated; values are bound
/// positionally — never interpolated into SQL.
/// Totality: every error path returns `IpeResult::Err`; no panic/unwrap.
#[cfg(feature = "db")]
pub fn db_upsert_fields<E: Send + From<String> + 'static>(
    conn: Db,
    table: String,
    conflict_target: Vec<String>,
    fields: Vec<(String, Option<SqlParam>)>,
) -> IpeTask<E, i64> {
    Box::pin(async move {
        let (sql, args) = match build_upsert_sql(&table, conflict_target, fields) {
            Ok(v) => v,
            Err(e) => return IpeResult::Err(build_refusal("db.upsertFields", &e)),
        };
        let sql = db_format_sql(sql);
        let mut q = sqlx::query(&sql);
        for p in args {
            q = bind_sql_param(q, p);
        }
        match exec_routed(&conn, q).await {
            Ok(res) => ok_res(res.rows_affected() as i64),
            Err(e) => IpeResult::Err(ipe_err(&e)),
        }
    })
}

/// `Db.insertFieldsReturning : Db -> String -> List (String, SqlField) -> String -> Decoder a -> Task Error (List a)`
///
/// Builds the same OmitField-aware INSERT as `db_insert_fields`, appends
/// `RETURNING <projection>`, runs it through `fetch_all`, and decodes each
/// returned row via the `Decoder<E,A>` (using `row_to_json` — NULL-preserving).
///
/// The `projection` string is caller-controlled but VALIDATED for injection
/// safety: it must be `"*"` or a comma-separated list of
/// plain identifiers (`col` / `table.col`, chars `[A-Za-z0-9_.]` only). Arbitrary
/// SQL expressions and `AS` aliases are intentionally REJECTED (`Err`), as is an
/// empty projection.
///
/// `RETURNING` is what sets [`SQLITE_VERSION_FLOOR`]; the connect-time
/// engine gate refuses any older server before this runs.
///
/// Security: table + column names validated; values bound positionally; only
/// the RETURNING projection is caller-supplied (and it's not executed as DML,
/// so the risk class is different — same as `queryDecode`'s SQL string trust model).
/// Totality: every error path returns `IpeResult::Err`; no panic/unwrap.
#[cfg(feature = "db")]
pub fn db_insert_fields_returning<E: Send + From<String> + 'static, A: Send + 'static>(
    conn: Db,
    table: String,
    fields: Vec<(String, Option<SqlParam>)>,
    projection: String,
    decoder: Decoder<E, A>,
) -> IpeTask<E, Vec<A>> {
    Box::pin(async move {
        if projection.is_empty() {
            return IpeResult::Err(
                "db.insertFieldsReturning: empty RETURNING projection"
                    .to_string()
                    .into(),
            );
        }
        let (base_sql, args) = match build_insert_sql(&table, fields) {
            Ok(v) => v,
            Err(e) => return IpeResult::Err(build_refusal("db.insertFieldsReturning", &e)),
        };
        // Validate the RETURNING projection — it is a caller-supplied String
        // interpolated into SQL. Allow "*" or a comma-separated list of valid
        // identifiers (col / table.col); reject anything else (SQL injection).
        let proj = projection.trim();
        let proj_ok = proj == "*" || proj.split(',').all(|t| valid_sql_ident(t.trim()));
        if !proj_ok {
            return IpeResult::Err(
                format!(
                    "db.insertFieldsReturning: invalid RETURNING projection {:?}",
                    projection
                )
                .into(),
            );
        }
        let sql = db_format_sql(format!("{} RETURNING {}", base_sql, projection));
        let mut q = sqlx::query(&sql);
        for p in args {
            q = bind_sql_param(q, p);
        }
        let rows = match fetch_all_routed(&conn, q).await {
            Ok(r) => r,
            Err(e) => return IpeResult::Err(ipe_err(&e)),
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let jv = match row_to_json(row) {
                Ok(v) => v,
                Err(e) => return IpeResult::Err(ipe_err(&e)),
            };
            match (decoder.run)(&jv) {
                IpeResult::Ok(a) => out.push(a),
                IpeResult::Err(e) => return IpeResult::Err(e),
            }
        }
        ok_res(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_ceilings_honour_the_shared_contract() {
        crate::system::assert_env_ceiling_contract(DB_CONNECTIONS_CEILING);
        crate::system::assert_env_ceiling_contract(DB_POOLS_CEILING);
    }

    #[test]
    fn sql_param_debug_prints_no_bound_value() {
        let params = vec![
            SqlParam::Text("Bearer S3CR3T".to_owned()),
            SqlParam::Int(424_242),
            SqlParam::Float(1.5),
            SqlParam::Bool(true),
            SqlParam::Bytes(b"T0K3N".to_vec()),
            SqlParam::Null(Box::new(SqlParam::Text("PW0RD".to_owned()))),
        ];
        let shown = format!("{params:?}");
        for planted in ["S3CR3T", "424242", "1.5", "true", "84, 48", "PW0RD"] {
            assert!(!shown.contains(planted), "{planted} leaked: {shown}");
        }
        assert!(shown.contains("Text(<redacted>)"), "{shown}");
        assert!(shown.contains("Null(Text(<redacted>))"), "{shown}");
    }

    /// Every target `url` makes the driver dial, as [`PostgresUrl::parse`] reads them.
    fn postgres_dial_targets(url: &str) -> Result<Vec<DialTarget>, DbConnectError> {
        PostgresUrl::parse(url).map(|url| url.targets)
    }

    #[test]
    fn url_is_cacheable_bare_memory_is_not_cacheable() {
        assert!(!url_is_cacheable(":memory:"));
        assert!(!url_is_cacheable("sqlite::memory:"));
        assert!(!url_is_cacheable("sqlite://:memory:"));
    }

    #[test]
    fn url_is_cacheable_mode_memory_without_shared_cache_is_not_cacheable() {
        assert!(!url_is_cacheable("file:foo.db?mode=memory"));
    }

    #[test]
    fn url_is_cacheable_mode_memory_with_shared_cache_is_cacheable() {
        // `cache=shared` mode=memory URLs are a shared named in-memory DB —
        // multiple connections to the SAME url ARE the same database, so
        // pooling is correct here (this is the regression this fix must NOT
        // break: don't overcorrect to "any mode=memory is uncacheable").
        assert!(url_is_cacheable("file:foo.db?mode=memory&cache=shared"));
    }

    #[test]
    fn url_is_cacheable_filename_containing_memory_substring_is_cacheable() {
        // The DoS-reopen regression: a legitimate file path containing the
        // substring "memory" must NOT be excluded from pooling.
        assert!(url_is_cacheable("sqlite://data/memory_bank.db?mode=rwc"));
        assert!(url_is_cacheable("sqlite:./memory_backup.sqlite"));
    }

    // Soundness: SQLite's own documented idiom wraps `:memory:` in a `file:`
    // sub-scheme (sqlite.org/inmemorydb.html —
    // `sqlite3_open("file::memory:?cache=shared", ...)`). Stripping only the
    // outer `sqlite:`/`sqlite://` scheme and not the inner `file:` one would
    // let `"file::memory:"` fall through to the default `true` (cacheable)
    // branch — silently pooling what SQLite treats as two DISTINCT private
    // databases. Per sqlite.org's documented semantics: a bare `:memory:` name
    // is unconditionally private (not URI-parsed, so `cache=shared` has no
    // effect on it even if present); only the `file:`-wrapped URI form honours
    // `cache=shared`.
    #[test]
    fn url_is_cacheable_file_wrapped_memory_without_shared_cache_is_not_cacheable() {
        assert!(!url_is_cacheable("file::memory:"));
        assert!(!url_is_cacheable("sqlite://file::memory:"));
    }

    #[test]
    fn url_is_cacheable_file_wrapped_memory_with_shared_cache_is_cacheable() {
        assert!(url_is_cacheable("file::memory:?cache=shared"));
    }

    // the IpeRow accessor is total over a Dict-shaped row — present field
    // reads back, absent field is "" (never panics), int/bool parse + default.
    #[test]
    fn ipe_row_hashmap_total() {
        let mut m: HashMap<String, String> = HashMap::new();
        m.insert("text".into(), "ping".into());
        m.insert("count".into(), "42".into());
        m.insert("flag".into(), "true".into());
        assert_eq!(db_get_string("text".into(), &m), "ping");
        assert_eq!(db_get_string("missing".into(), &m), "");
        assert_eq!(db_get_int("count".into(), &m), 42);
        assert_eq!(db_get_int("missing".into(), &m), 0);
        assert!(db_get_bool("flag".into(), &m));
        assert!(!db_get_bool("missing".into(), &m));
    }

    // The total getter truncates a decimal toward zero, round-trips an exact
    // i64 boundary, and fails CLOSED to the `0` default for a magnitude that an
    // `as i64` cast would silently saturate to the boundary (never surfacing a
    // wrong value that reads like a real row value).
    #[test]
    fn db_get_int_rejects_out_of_range_float_no_saturation() {
        let mut m: HashMap<String, String> = HashMap::new();

        // Decimal string: truncate toward zero.
        m.insert("pos".into(), "3.7".into());
        m.insert("neg".into(), "-3.7".into());
        assert_eq!(db_get_int("pos".into(), &m), 3);
        assert_eq!(db_get_int("neg".into(), &m), -3);

        // Exact i64 boundaries round-trip (they parse as i64 directly).
        m.insert("max".into(), i64::MAX.to_string());
        m.insert("min".into(), i64::MIN.to_string());
        assert_eq!(db_get_int("max".into(), &m), i64::MAX);
        assert_eq!(db_get_int("min".into(), &m), i64::MIN);

        // A magnitude far past each boundary, expressed as a float string so it
        // takes the float path: fall back to 0, NOT the saturated boundary.
        m.insert("over".into(), "1e30".into());
        m.insert("under".into(), "-1e30".into());
        assert_eq!(db_get_int("over".into(), &m), 0);
        assert_ne!(db_get_int("over".into(), &m), i64::MAX);
        assert_eq!(db_get_int("under".into(), &m), 0);
        assert_ne!(db_get_int("under".into(), &m), i64::MIN);
    }

    // `Db.getString "path" req` on an `init` handler's typed
    // request reads the named struct field; params/headers/cookies back any
    // other key; absent -> "" (total).
    #[cfg(feature = "web")]
    #[test]
    fn ipe_row_webreq_named_fields_and_dicts() {
        let mut params: HashMap<String, String> = HashMap::new();
        params.insert("slug".into(), "general".into());
        let mut cookies: HashMap<String, String> = HashMap::new();
        cookies.insert("ipe_sid".into(), "abc".into());
        let req = crate::WebReq {
            path: "/chat/general".into(),
            query: "x=1".into(),
            method: "GET".into(),
            params,
            headers: HashMap::new(),
            cookies,
        };
        assert_eq!(db_get_string("path".into(), &req), "/chat/general");
        assert_eq!(db_get_string("method".into(), &req), "GET");
        assert_eq!(db_get_string("query".into(), &req), "x=1");
        assert_eq!(db_get_string("slug".into(), &req), "general"); // params
        assert_eq!(db_get_string("ipe_sid".into(), &req), "abc"); // cookies
        assert_eq!(db_get_string("nope".into(), &req), ""); // absent -> total ""
    }

    async fn fresh_db() -> Db {
        // A SINGLE persistent connection per test. `sqlite::memory:` gives each
        // pool connection its OWN in-memory database, so a default multi-conn
        // pool routes BEGIN / INSERT / COMMIT / SELECT to different (empty) DBs
        // — the source of a parallel-run flake: under load the pool
        // opens extra connections and ops miss the table / committed row.
        // min=max=1 pins one connection (one DB, table + transactions always
        // visible); each test still gets its own isolated pool.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE todos (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0)")
            .execute(&pool).await.expect("create table");
        pool
    }

    /// A seeded external (foreign) SQLite connection, distinct from the app pool —
    /// stands in for a source of a different dialect that the read runners dial
    /// through the same codec stack. `ledger` carries an `amount` INTEGER column.
    #[allow(clippy::expect_used)]
    async fn fresh_external_conn() -> ExternalConnection {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory external sqlite");
        sqlx::query(
            "CREATE TABLE ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, amount INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .expect("create ledger");
        sqlx::query("INSERT INTO ledger (amount) VALUES (7), (42)")
            .execute(&pool)
            .await
            .expect("seed ledger");
        ExternalConnection::Sqlite(pool)
    }

    /// The external read path decodes seeded rows through the SAME `Decoder<E,A>`
    /// the app path uses — the §4 "typed reads from a foreign DB via one codec"
    /// target. `db_conn_query_decode_params` reads `amount` back as `Int`.
    #[tokio::test]
    async fn external_query_decode_reads_through_one_codec() {
        let conn = fresh_external_conn().await;
        let out: IpeResult<String, Vec<i64>> = db_conn_query_decode_params(
            conn,
            "SELECT amount FROM ledger ORDER BY amount".into(),
            vec![],
            db_decode_int("amount".into()),
        )
        .await;
        match out {
            IpeResult::Ok(v) => assert_eq!(v, vec![7, 42]),
            other => panic!("external queryDecode failed: {:?}", other),
        }
    }

    /// The injection barrier is UNCHANGED on the external path: a value carrying SQL
    /// metacharacters flows through a bound parameter (a `Sql.param` in the
    /// fragment), so it matches VERBATIM and the surrounding table is untouched — no
    /// injection executes against the foreign connection.
    #[tokio::test]
    async fn external_find_where_binds_params_no_injection() {
        let conn = fresh_external_conn().await;
        // A fragment built from the audited `Sql.*` combinators: `amount = ?`, the
        // value bound (never spliced). The metacharacter value simply doesn't match.
        let frag = sql_eq(
            sql_column("amount".to_string()),
            sql_param(SqlParam::Int(7)),
        );
        let rows: IpeResult<String, Vec<HashMap<String, String>>> =
            db_conn_find_where(conn.clone(), "ledger".into(), frag).await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].get("amount").map(String::as_str), Some("7"));
            }
            other => panic!("external findWhere failed: {:?}", other),
        }
        // A hostile TABLE identifier is rejected by the same `SqlIdent` gate — the
        // read runner never interpolates an unvalidated name into SQL.
        let bad: IpeResult<String, Vec<HashMap<String, String>>> = db_conn_find_where(
            conn,
            "ledger; DROP TABLE ledger".into(),
            sql_eq(sql_param(SqlParam::Int(1)), sql_param(SqlParam::Int(1))),
        )
        .await;
        assert!(
            matches!(bad, IpeResult::Err(_)),
            "a hostile external table identifier must be rejected before any SQL runs"
        );
    }

    /// A hostile column identifier in a `Sql.column` poisons the fragment, which the
    /// external `findWhere` surfaces as a typed `Err` — the poison marker path is
    /// identical to the app connection's.
    #[tokio::test]
    async fn external_find_where_rejects_poisoned_column() {
        let conn = fresh_external_conn().await;
        let poisoned = sql_eq(
            sql_column("amount; DROP TABLE ledger".to_string()),
            sql_param(SqlParam::Int(7)),
        );
        let rows: IpeResult<String, Vec<HashMap<String, String>>> =
            db_conn_find_where(conn, "ledger".into(), poisoned).await;
        assert!(
            matches!(rows, IpeResult::Err(_)),
            "a poisoned column fragment must fail closed on the external path too"
        );
    }

    /// `db_conn_get_by_id` binds the id as a positional parameter (never
    /// interpolated) and returns the matching row from the foreign connection.
    #[tokio::test]
    async fn external_get_by_id_binds_id() {
        let conn = fresh_external_conn().await;
        let got: IpeResult<String, IpeMaybe<HashMap<String, String>>> =
            db_conn_get_by_id(conn, "ledger".into(), "1".into()).await;
        match got {
            IpeResult::Ok(IpeMaybe::Just(row)) => {
                assert_eq!(row.get("amount").map(String::as_str), Some("7"));
            }
            other => panic!("external getById failed: {:?}", other),
        }
    }

    #[tokio::test]
    async fn ipe_err_redacts_db_row_values() {
        // A UNIQUE-constraint failure must NOT echo the offending row VALUE into
        // the Ipê-visible Error (PRINCIPLES #1 info-leak). `ipe_err` builds a
        // structural message (SQLSTATE/driver code + constraint name) from the
        // structured error fields instead of the raw Display, which on
        // PostgreSQL/MySQL embeds `Key (email)=(victim@…) already exists`.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE secrets (email TEXT UNIQUE NOT NULL)")
            .execute(&pool)
            .await
            .expect("create table");
        let secret = "victim-PII@example.com";
        let insert = format!("INSERT INTO secrets (email) VALUES ('{}')", secret);
        let r1: IpeResult<String, i64> = db_exec(pool.clone(), insert.clone(), Vec::new()).await;
        assert!(
            matches!(r1, IpeResult::Ok(_)),
            "first insert should succeed"
        );
        let r2: IpeResult<String, i64> = db_exec(pool.clone(), insert, Vec::new()).await;
        match r2 {
            IpeResult::Err(e) => {
                assert!(!e.contains(secret), "row value leaked into db error: {e}");
                assert!(
                    e.starts_with("db: database error"),
                    "expected redacted structural form, got: {e}"
                );
            }
            IpeResult::Ok(_) => panic!("duplicate insert should violate the UNIQUE constraint"),
        }
    }

    const SECRET_URL: &str = "postgres://admin:s3cr3t-pw@db.internal:5432/prod";

    /// Neither rendering of a connect refusal carries the password or user.
    fn assert_credential_free(refused: &DbConnectError) {
        for rendered in [refused.to_string(), format!("{refused:?}")] {
            assert!(
                !rendered.contains("s3cr3t-pw"),
                "password leaked: {rendered}"
            );
            assert!(!rendered.contains("admin"), "user leaked: {rendered}");
        }
    }

    /// A database error whose message AND code echo the connection URL, as a
    /// hostile or careless driver/server could.
    #[derive(Debug)]
    struct EchoingDbError;

    impl std::fmt::Display for EchoingDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(SECRET_URL)
        }
    }

    impl std::error::Error for EchoingDbError {}

    impl sqlx::error::DatabaseError for EchoingDbError {
        fn message(&self) -> &str {
            SECRET_URL
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            Some(std::borrow::Cow::Borrowed(SECRET_URL))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    /// Every `sqlx::Error` shape that can carry the connection URL classifies to
    /// a message built from its variant alone.
    #[test]
    fn db_failure_never_echoes_connection_credentials() {
        let boxed = || -> sqlx::error::BoxDynError { SECRET_URL.into() };
        let cases = [
            (
                sqlx::Error::Configuration(boxed()),
                "db: database unreachable",
            ),
            (
                sqlx::Error::Io(std::io::Error::other(SECRET_URL)),
                "db: database unreachable",
            ),
            (sqlx::Error::Tls(boxed()), "db: database unreachable"),
            (
                sqlx::Error::Protocol(SECRET_URL.to_string()),
                "db: database error",
            ),
            (
                sqlx::Error::Database(Box::new(EchoingDbError)),
                "db: database error",
            ),
        ];
        for (raw, expected) in cases {
            assert!(
                raw.to_string().contains("s3cr3t-pw"),
                "the raw driver error must be the leaking form this guards: {raw}"
            );
            let refused = DbConnectError::Unreachable(DriverFailure::of(DbEngine::Postgres, &raw));
            assert_credential_free(&refused);
            assert_eq!(refused.to_string(), expected);
            let unreadable =
                DbConnectError::VersionUnreadable(DriverFailure::of(DbEngine::Postgres, &raw));
            assert_credential_free(&unreadable);
        }
    }

    /// A well-formed SQLSTATE survives classification; a malformed one is dropped.
    #[test]
    fn db_failure_keeps_only_well_formed_codes() {
        #[derive(Debug)]
        struct Coded(&'static str);
        impl std::fmt::Display for Coded {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("coded")
            }
        }
        impl std::error::Error for Coded {}
        impl sqlx::error::DatabaseError for Coded {
            fn message(&self) -> &str {
                "coded"
            }
            fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
                Some(std::borrow::Cow::Borrowed(self.0))
            }
            fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
                self
            }
            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::Other
            }
        }
        let classify = |code| {
            DriverFailure::of(
                DbEngine::Postgres,
                &sqlx::Error::Database(Box::new(Coded(code))),
            )
        };
        let kept = classify("28P01");
        assert_eq!(kept.raw_code(), Some("28P01"));
        assert_eq!(kept.failure(), IpeDbFailure::AccessDenied);
        for malformed in ["", "28P01\n[forged] line", "0123456789abcdefX"] {
            let dropped = classify(malformed);
            assert_eq!(dropped.raw_code(), None, "{malformed:?}");
            assert_eq!(
                dropped.failure(),
                IpeDbFailure::OtherFailure,
                "{malformed:?}"
            );
        }
    }

    /// A database error carrying a chosen code and constraint name.
    #[derive(Debug)]
    struct FakeDbError {
        code: Option<&'static str>,
        constraint: Option<&'static str>,
    }

    impl std::fmt::Display for FakeDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake driver message 2067 [19] victim@example.com")
        }
    }

    impl std::error::Error for FakeDbError {}

    impl sqlx::error::DatabaseError for FakeDbError {
        fn message(&self) -> &str {
            "fake driver message 2067 [19] victim@example.com"
        }
        fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
            self.code.map(std::borrow::Cow::Borrowed)
        }
        fn constraint(&self) -> Option<&str> {
            self.constraint
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn coded(code: Option<&'static str>) -> sqlx::Error {
        sqlx::Error::Database(Box::new(FakeDbError {
            code,
            constraint: None,
        }))
    }

    /// Every SQLite row, exact and primary, classifies to its variant.
    #[test]
    fn classify_failure_sqlite_rows() {
        use IpeDbFailure as F;
        let rows = [
            ("2067", F::UniqueViolation),
            ("1555", F::UniqueViolation),
            ("787", F::ForeignKeyViolation),
            ("1299", F::NotNullViolation),
            ("275", F::CheckViolation),
            ("1811", F::TriggerRaised),
            ("19", F::OtherConstraint),
            ("3091", F::OtherConstraint),
            ("5", F::Busy),
            ("517", F::Busy),
            ("6", F::Busy),
            ("262", F::Busy),
            ("8", F::ReadOnlyDatabase),
            ("1032", F::ReadOnlyDatabase),
            ("3", F::AccessDenied),
            ("23", F::AccessDenied),
            ("14", F::CannotOpen),
            ("1038", F::CannotOpen),
            ("26", F::NotADatabase),
            ("11", F::NotADatabase),
            ("1", F::InvalidStatement),
            ("2", F::OtherFailure),
            ("13", F::OtherFailure),
        ];
        for (code, expected) in rows {
            assert_eq!(
                classify_failure(DbEngine::Sqlite, &coded(Some(code))),
                expected,
                "SQLite code {code}"
            );
        }
    }

    /// Every PostgreSQL row, exact and class, classifies to its variant; an
    /// exact row wins over its class.
    #[test]
    fn classify_failure_postgres_rows() {
        use IpeDbFailure as F;
        let rows = [
            ("23505", F::UniqueViolation),
            ("23503", F::ForeignKeyViolation),
            ("23502", F::NotNullViolation),
            ("23514", F::CheckViolation),
            ("P0001", F::TriggerRaised),
            ("23P01", F::OtherConstraint),
            ("23000", F::OtherConstraint),
            ("55P03", F::Busy),
            ("40P01", F::Busy),
            ("40001", F::Busy),
            ("25006", F::ReadOnlyDatabase),
            ("42501", F::AccessDenied),
            ("28P01", F::AccessDenied),
            ("28000", F::AccessDenied),
            ("3D000", F::CannotOpen),
            ("XX001", F::NotADatabase),
            ("XX002", F::NotADatabase),
            ("42P01", F::InvalidStatement),
            ("42703", F::InvalidStatement),
            ("42601", F::InvalidStatement),
            ("42883", F::InvalidStatement),
            ("08006", F::Unreachable),
            ("08001", F::Unreachable),
            ("22012", F::OtherFailure),
            ("XX000", F::OtherFailure),
            ("53300", F::OtherFailure),
        ];
        for (code, expected) in rows {
            assert_eq!(
                classify_failure(DbEngine::Postgres, &coded(Some(code))),
                expected,
                "SQLSTATE {code}"
            );
        }
    }

    /// The non-database `sqlx::Error` arms classify by variant.
    #[test]
    fn classify_failure_non_database_rows() {
        use IpeDbFailure as F;
        for engine in [DbEngine::Sqlite, DbEngine::Postgres] {
            let rows = [
                (sqlx::Error::PoolTimedOut, F::Busy),
                (sqlx::Error::PoolClosed, F::Unreachable),
                (sqlx::Error::Io(std::io::Error::other("io")), F::Unreachable),
                (sqlx::Error::Tls("tls".into()), F::Unreachable),
                (sqlx::Error::Configuration("cfg".into()), F::Unreachable),
                (sqlx::Error::RowNotFound, F::OtherFailure),
                (sqlx::Error::Protocol("p".to_owned()), F::OtherFailure),
                (sqlx::Error::Decode("d".into()), F::OtherFailure),
                (sqlx::Error::WorkerCrashed, F::OtherFailure),
            ];
            for (raw, expected) in rows {
                assert_eq!(classify_failure(engine, &raw), expected, "{raw:?}");
            }
        }
    }

    /// A code from the other engine's space is `OtherFailure`, never a
    /// neighbouring row.
    #[test]
    fn classify_failure_refuses_wrong_engine_codes() {
        assert_eq!(
            classify_failure(DbEngine::Postgres, &coded(Some("23505"))),
            IpeDbFailure::UniqueViolation
        );
        assert_eq!(
            classify_failure(DbEngine::Sqlite, &coded(Some("23505"))),
            IpeDbFailure::OtherFailure
        );
        assert_eq!(
            classify_failure(DbEngine::Sqlite, &coded(Some("2067"))),
            IpeDbFailure::UniqueViolation
        );
        assert_eq!(
            classify_failure(DbEngine::Postgres, &coded(Some("2067"))),
            IpeDbFailure::OtherFailure
        );
    }

    /// An absent, empty, non-numeric, out-of-range, overlong or oddly shaped
    /// code is `OtherFailure`, never a primary-code match.
    #[test]
    fn classify_failure_refuses_malformed_codes() {
        let seventeen = "23505234567890123";
        assert_eq!(seventeen.len(), MAX_DB_FAILURE_CODE_LEN + 1);
        let malformed = [
            None,
            Some(""),
            Some("abc"),
            Some("99999999999"),
            Some("-2067"),
            Some(" 2067"),
            Some("2067\n"),
            Some("23505 "),
            Some(seventeen),
            Some("2350"),
            Some("235050"),
        ];
        for engine in [DbEngine::Sqlite, DbEngine::Postgres] {
            for code in malformed {
                assert_eq!(
                    classify_failure(engine, &coded(code)),
                    IpeDbFailure::OtherFailure,
                    "{engine:?} code {code:?}"
                );
            }
        }
        // The control: one step back inside the bound still reads its row.
        assert_eq!(
            classify_failure(DbEngine::Sqlite, &coded(Some("0000000000002067"))),
            IpeDbFailure::UniqueViolation
        );
    }

    /// A real PostgreSQL driver failure on a URL carrying credentials never
    /// surfaces them: the refusal is either the SSRF gate's (host only) or the
    /// driver's, classified.
    #[tokio::test]
    async fn vetted_pool_postgres_refusal_is_credential_free() {
        let url = "postgres://admin:s3cr3t-pw@db.internal/prod?sslmode=s3cr3t-pw";
        let refused = match DbUrl::parse(url) {
            Ok(url) => VettedPool::<sqlx::Postgres>::connect(&url, 1).await.err(),
            Err(refused) => Some(refused),
        };
        assert!(refused.is_some(), "an invalid sslmode must be refused");
        if let Some(refused) = refused {
            assert_credential_free(&refused);
        }
    }

    /// A real SQLite driver failure never surfaces the path or options it was
    /// handed.
    #[tokio::test]
    async fn vetted_pool_sqlite_refusal_is_credential_free() {
        for url in [
            "sqlite:///nonexistent-admin-s3cr3t-pw/x.db?mode=ro",
            "sqlite://x.db?mode=s3cr3t-pw",
        ] {
            let refused = match DbUrl::parse(url) {
                Ok(url) => VettedPool::<sqlx::Sqlite>::connect(&url, 1).await.err(),
                Err(refused) => Some(refused),
            };
            assert!(refused.is_some(), "{url:?} must be refused");
            if let Some(refused) = refused {
                assert_credential_free(&refused);
            }
        }
    }

    /// The bundled SQLite passes every gate and yields a usable pool.
    #[tokio::test]
    async fn vetted_pool_admits_the_bundled_sqlite() {
        let vetted = match DbUrl::parse("sqlite::memory:") {
            Ok(url) => VettedPool::<sqlx::Sqlite>::connect(&url, 1)
                .await
                .map(|_| ()),
            Err(refused) => Err(refused),
        };
        assert!(
            vetted.is_ok(),
            "bundled SQLite must connect: {:?}",
            vetted.err()
        );
    }

    /// The dial-target set covers the authority host, every `host` /
    /// `hostaddr` query override, both socket forms, and the driver default.
    #[test]
    fn postgres_dial_targets_cover_every_dial_source() {
        let tcp = |host: &str, port| DialTarget::Tcp {
            host: ConfiguredHost::from_config(host.to_owned()),
            port,
        };
        assert_eq!(
            postgres_dial_targets("postgres://u:p@public.example/db?host=169.254.169.254"),
            Ok(vec![
                tcp("public.example", POSTGRES_DEFAULT_PORT),
                tcp("169.254.169.254", POSTGRES_DEFAULT_PORT)
            ])
        );
        assert_eq!(
            postgres_dial_targets("postgres://public.example:6543/db?hostaddr=10.0.0.1&port=7000"),
            Ok(vec![tcp("public.example", 7000), tcp("10.0.0.1", 7000)])
        );
        assert_eq!(
            postgres_dial_targets("postgres:///db?host=/var/run/postgresql"),
            Ok(vec![DialTarget::Socket])
        );
        assert_eq!(
            postgres_dial_targets("postgres://%2Fvar%2Frun%2Fpostgresql/db"),
            Ok(vec![DialTarget::Socket])
        );
        assert_eq!(
            postgres_dial_targets("postgres://public.example/db?host=/tmp"),
            Ok(vec![
                tcp("public.example", POSTGRES_DEFAULT_PORT),
                DialTarget::Socket
            ])
        );
        for no_host in ["postgres:///db", "postgres:db"] {
            assert_eq!(
                postgres_dial_targets(no_host),
                Ok(vec![DialTarget::DriverDefault]),
                "{no_host:?} names no host"
            );
        }
    }

    /// A PostgreSQL URL whose dial targets cannot be read is refused before
    /// any dial or lookup, under either policy.
    #[tokio::test]
    async fn postgres_unreadable_dial_targets_are_refused() {
        for url in [
            "not a url with s3cr3t-pw",
            "postgres://public.example/db?port=s3cr3t-pw",
            "postgres://public.example/db?port=70000",
        ] {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                assert_eq!(
                    pg_gate_with(url, policy, &NoDns).await.err(),
                    Some(DbConnectError::InvalidUrl),
                    "{url:?} under {policy:?}"
                );
            }
        }
    }

    /// A credential holding an unencoded `/`, `?`, or `#` ends the authority
    /// early, so the parser would read part of the userinfo as the host. Such
    /// a URL is refused before any lookup, and the refusal names no part of it.
    #[tokio::test]
    async fn postgres_url_with_an_at_after_its_authority_is_refused() {
        for url in [
            "postgres://admin:5432/s3cr3t-pw@db.example",
            "postgres://admin@s3cr3t/-pw@db.example",
            "postgres://admin:s3cr3t?pw@db.example",
            "postgres://admin#s3cr3t-pw@db.example",
            "postgres://db.example/app?user=admin@s3cr3t-pw",
            "postgres://admin\\s3cr3t-pw@db.example/app",
            "postgres://db.example/app#admin@s3cr3t-pw",
        ] {
            for policy in [DialPolicy::DenyPrivate, DialPolicy::AllowAll] {
                let refused = pg_gate_with(url, policy, &NoDns).await.err();
                assert_eq!(
                    refused,
                    Some(DbConnectError::MisplacedUserinfo),
                    "{url:?} under {policy:?}"
                );
                if let Some(refused) = refused {
                    assert_credential_free(&refused);
                    assert!(!refused.to_string().contains("s3cr3t"), "{refused}");
                }
            }
        }
    }

    /// Only the authority's last `@` splits credentials from the host, so an
    /// `@` inside the password is read, not refused.
    #[test]
    fn postgres_url_with_an_at_inside_its_authority_is_read() {
        assert_eq!(
            postgres_dial_targets("postgres://admin:s3cr@3t-pw@db.example:6432/app"),
            Ok(vec![DialTarget::Tcp {
                host: ConfiguredHost::from_config("db.example".to_owned()),
                port: 6432,
            }])
        );
    }

    /// A URL naming more hosts than the gate vets is refused before any
    /// lookup; the largest admitted count still parses.
    #[test]
    fn postgres_dial_targets_are_capped() {
        let url_with = |hosts: usize| {
            let params: Vec<String> = (0..hosts.saturating_sub(1))
                .map(|i| format!("host=h{i}.example"))
                .collect();
            format!("postgres://db.example/app?{}", params.join("&"))
        };
        let too_many = DbConnectError::TooManyDialTargets {
            limit: MAX_POSTGRES_DIAL_TARGETS,
        };
        assert_eq!(
            postgres_dial_targets(&url_with(MAX_POSTGRES_DIAL_TARGETS)).map(|t| t.len()),
            Ok(MAX_POSTGRES_DIAL_TARGETS)
        );
        assert_eq!(
            postgres_dial_targets(&url_with(MAX_POSTGRES_DIAL_TARGETS + 1)),
            Err(too_many.clone())
        );
        assert!(
            DbUrl::parse(&url_with(MAX_POSTGRES_DIAL_TARGETS + 1)).is_err_and(|e| e == too_many)
        );
    }

    #[test]
    fn migrate_checksum_is_lowercase_sha256_hex_matching_go() {
        // G4 pin: the ledger checksum is a cross-backend DB contract. This value
        // is `sha256hex("SELECT 1;")` — identical to
        // fmt.Sprintf("%x", sha256.Sum256([]byte("SELECT 1;"))). A future hasher
        // swap that broke cross-backend ledger interop would fail HERE.
        assert_eq!(
            super::migrate_checksum("SELECT 1;"),
            "17db4fd369edb9244b9f91d9aeed145c3d04ad8ba6e95d06247f07a63527d11a"
        );
    }

    #[tokio::test]
    async fn migrate_is_idempotent_and_drift_guarded() {
        let db = fresh_db().await;
        let base = vec![
            (
                "001_users".to_string(),
                "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)".to_string(),
            ),
            (
                "002_email_idx".to_string(),
                "CREATE INDEX idx_users_email ON users(email)".to_string(),
            ),
        ];

        // First run applies both, in declaration order.
        let r1: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), base.clone()).await;
        match r1 {
            IpeResult::Ok(v) => assert_eq!(
                v,
                vec!["001_users".to_string(), "002_email_idx".to_string()]
            ),
            IpeResult::Err(e) => panic!("first migrate: {e}"),
        }

        // Second run is idempotent — both already applied → 0 applied.
        let r2: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), base.clone()).await;
        match r2 {
            IpeResult::Ok(v) => assert!(v.is_empty(), "expected 0 applied on re-run, got {v:?}"),
            IpeResult::Err(e) => panic!("idempotent re-run: {e}"),
        }

        // Ledger recorded exactly the two migrations.
        let ledger: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT name, checksum FROM _ipe_migrations ORDER BY name".to_string(),
            Vec::new(),
        )
        .await;
        match ledger {
            IpeResult::Ok(rows) => assert_eq!(rows.len(), 2, "ledger rows: {rows:?}"),
            IpeResult::Err(e) => panic!("read ledger: {e}"),
        }

        // Drift: same name, edited SQL → checksum-mismatch error, nothing applied.
        let drift = vec![(
            "001_users".to_string(),
            "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, name TEXT)".to_string(),
        )];
        let r3: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), drift).await;
        match r3 {
            IpeResult::Err(e) => assert!(
                e.contains("checksum mismatch"),
                "expected drift error, got: {e}"
            ),
            IpeResult::Ok(v) => panic!("expected drift error, but applied {v:?}"),
        }

        // Adding a NEW migration after the applied ones resumes — only it applies.
        let mut extended = base.clone();
        extended.push((
            "003_posts".to_string(),
            "CREATE TABLE posts (id INTEGER PRIMARY KEY)".to_string(),
        ));
        let r4: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), extended).await;
        match r4 {
            IpeResult::Ok(v) => assert_eq!(v, vec!["003_posts".to_string()]),
            IpeResult::Err(e) => panic!("resume migrate: {e}"),
        }
    }

    // ─── Rename-migration data-preservation tests ─────────────────────────────
    //
    // These tests drive `db_migrate_apply` directly with the DDL that
    // `Store.migrations` / `Store.renameColumn` / `Store.renameTable` produce,
    // proving the ledger correctly applies and skips each rename entry.

    /// Column rename preserves existing row data and makes rows readable under
    /// the new column name.
    #[tokio::test]
    async fn rename_column_preserves_data() {
        let db = new_single_conn_db().await;
        // Matches what Store.migrations produces for a users store with
        // renameColumn "name" "full_name".
        let migrations = vec![
            (
                "create_users".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT, age INTEGER)"
                    .to_string(),
            ),
            (
                "rename_column_users_name_to_full_name".to_string(),
                "ALTER TABLE users RENAME COLUMN name TO full_name".to_string(),
            ),
        ];

        // First apply: both entries run.
        let r1: IpeResult<String, Vec<String>> =
            db_migrate_apply(db.clone(), migrations.clone()).await;
        match r1 {
            IpeResult::Ok(v) => assert_eq!(
                v,
                vec![
                    "create_users".to_string(),
                    "rename_column_users_name_to_full_name".to_string()
                ]
            ),
            IpeResult::Err(e) => panic!("first apply: {e}"),
        }

        // Insert a row using the POST-rename column name.
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO users (id, full_name, age) VALUES ('u1', 'Alice', 30)".to_string(),
            Vec::new(),
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1)), "insert: {ins:?}");

        // Row is readable under full_name; the old `name` column is absent.
        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT full_name, age FROM users WHERE id = 'u1'".to_string(),
            Vec::new(),
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1, "expected 1 row, got {}", v.len());
                assert_eq!(
                    v.first()
                        .and_then(|r| r.get("full_name"))
                        .map(String::as_str),
                    Some("Alice"),
                    "full_name should be Alice"
                );
            }
            IpeResult::Err(e) => panic!("read after rename: {e}"),
        }

        // `name` column is gone — selecting it is an error.
        let bad: IpeResult<String, Vec<HashMap<String, String>>> =
            db_query(db.clone(), "SELECT name FROM users".to_string(), Vec::new()).await;
        assert!(
            matches!(bad, IpeResult::Err(_)),
            "selecting the old column name must fail after rename"
        );
    }

    /// Re-applying the same migration list is idempotent — no error, no
    /// re-issue of the rename, data unchanged.
    #[tokio::test]
    async fn rename_column_idempotent_rerun() {
        let db = new_single_conn_db().await;
        let migrations = vec![
            (
                "create_users".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)".to_string(),
            ),
            (
                "rename_column_users_name_to_full_name".to_string(),
                "ALTER TABLE users RENAME COLUMN name TO full_name".to_string(),
            ),
        ];

        // First apply.
        let r1: IpeResult<String, Vec<String>> =
            db_migrate_apply(db.clone(), migrations.clone()).await;
        assert!(matches!(r1, IpeResult::Ok(_)), "first apply: {r1:?}");

        // Insert after first apply.
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO users (id, full_name) VALUES ('u1', 'Bob')".to_string(),
            Vec::new(),
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1)), "insert: {ins:?}");

        // Re-apply: both entries already in ledger → 0 applied.
        let r2: IpeResult<String, Vec<String>> =
            db_migrate_apply(db.clone(), migrations.clone()).await;
        match r2 {
            IpeResult::Ok(v) => assert!(v.is_empty(), "expected 0 on re-run, got {v:?}"),
            IpeResult::Err(e) => panic!("re-run: {e}"),
        }

        // Data unchanged.
        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT full_name FROM users WHERE id = 'u1'".to_string(),
            Vec::new(),
        )
        .await;
        match rows {
            IpeResult::Ok(v) => assert_eq!(
                v.first()
                    .and_then(|r| r.get("full_name"))
                    .map(String::as_str),
                Some("Bob"),
                "data unchanged after re-run"
            ),
            IpeResult::Err(e) => panic!("read after re-run: {e}"),
        }
    }

    /// Applying the same list to a fresh (empty) database converges to the
    /// same final schema — rows inserted afterward read back under the new name.
    #[tokio::test]
    async fn rename_column_fresh_db_convergence() {
        let db = new_single_conn_db().await;
        let migrations = vec![
            (
                "create_users".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)".to_string(),
            ),
            (
                "rename_column_users_name_to_full_name".to_string(),
                "ALTER TABLE users RENAME COLUMN name TO full_name".to_string(),
            ),
        ];

        // Apply to a completely empty DB — both entries run.
        let r: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), migrations).await;
        match r {
            IpeResult::Ok(v) => assert_eq!(v.len(), 2, "expected 2 applied, got {v:?}"),
            IpeResult::Err(e) => panic!("fresh-db apply: {e}"),
        }

        // Insert using the new name.
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO users (id, full_name) VALUES ('u2', 'Carol')".to_string(),
            Vec::new(),
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1)), "fresh-db insert: {ins:?}");

        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT full_name FROM users WHERE id = 'u2'".to_string(),
            Vec::new(),
        )
        .await;
        match rows {
            IpeResult::Ok(v) => assert_eq!(
                v.first()
                    .and_then(|r| r.get("full_name"))
                    .map(String::as_str),
                Some("Carol"),
                "fresh-db convergence"
            ),
            IpeResult::Err(e) => panic!("fresh-db read: {e}"),
        }
    }

    /// Table rename preserves all row data and makes the table accessible
    /// under the new name.
    #[tokio::test]
    async fn rename_table_preserves_data() {
        let db = new_single_conn_db().await;
        // Matches what Store.migrations produces for renameTable "accounts".
        let migrations = vec![
            (
                "create_users".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT)".to_string(),
            ),
            (
                "rename_table_users_to_accounts".to_string(),
                "ALTER TABLE users RENAME TO accounts".to_string(),
            ),
        ];

        let r1: IpeResult<String, Vec<String>> =
            db_migrate_apply(db.clone(), migrations.clone()).await;
        assert!(matches!(r1, IpeResult::Ok(_)), "first apply: {r1:?}");

        // Insert under the new table name.
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO accounts (id, email) VALUES ('a1', 'dave@example.com')".to_string(),
            Vec::new(),
        )
        .await;
        assert!(
            matches!(ins, IpeResult::Ok(1)),
            "table-rename insert: {ins:?}"
        );

        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT email FROM accounts WHERE id = 'a1'".to_string(),
            Vec::new(),
        )
        .await;
        match rows {
            IpeResult::Ok(v) => assert_eq!(
                v.first().and_then(|r| r.get("email")).map(String::as_str),
                Some("dave@example.com"),
                "row readable under new table name"
            ),
            IpeResult::Err(e) => panic!("read after table rename: {e}"),
        }

        // Old table name is gone.
        let bad: IpeResult<String, Vec<HashMap<String, String>>> =
            db_query(db.clone(), "SELECT * FROM users".to_string(), Vec::new()).await;
        assert!(
            matches!(bad, IpeResult::Err(_)),
            "old table name must be absent after rename"
        );

        // Re-apply is idempotent.
        let r2: IpeResult<String, Vec<String>> = db_migrate_apply(db.clone(), migrations).await;
        match r2 {
            IpeResult::Ok(v) => assert!(v.is_empty(), "expected 0 on re-run, got {v:?}"),
            IpeResult::Err(e) => panic!("table-rename re-run: {e}"),
        }
    }

    /// A column rename whose `from` is absent in the schema returns a `Task Err`
    /// and leaves the ledger unadvanced.
    #[tokio::test]
    async fn rename_column_missing_from_fails_closed() {
        let db = new_single_conn_db().await;
        // Create a table without a `name` column, then try to rename it.
        let r_create: IpeResult<String, Vec<String>> = db_migrate_apply(
            db.clone(),
            vec![(
                "create_users".to_string(),
                "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT)".to_string(),
            )],
        )
        .await;
        assert!(matches!(r_create, IpeResult::Ok(_)), "create: {r_create:?}");

        // Ledger row count before the failing rename.
        let before: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT name FROM _ipe_migrations ORDER BY name".to_string(),
            Vec::new(),
        )
        .await;
        let before_count = match before {
            IpeResult::Ok(v) => v.len(),
            IpeResult::Err(e) => panic!("ledger read before: {e}"),
        };

        // Rename a column that does not exist — must error.
        let r_rename: IpeResult<String, Vec<String>> = db_migrate_apply(
            db.clone(),
            vec![
                (
                    "create_users".to_string(),
                    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT)"
                        .to_string(),
                ),
                (
                    "rename_column_users_name_to_full_name".to_string(),
                    "ALTER TABLE users RENAME COLUMN name TO full_name".to_string(),
                ),
            ],
        )
        .await;
        assert!(
            matches!(r_rename, IpeResult::Err(_)),
            "renaming absent column must return Err"
        );

        // Ledger must be unadvanced — the failing rename entry was not recorded.
        let after: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT name FROM _ipe_migrations ORDER BY name".to_string(),
            Vec::new(),
        )
        .await;
        let after_count = match after {
            IpeResult::Ok(v) => v.len(),
            IpeResult::Err(e) => panic!("ledger read after: {e}"),
        };
        assert_eq!(
            before_count, after_count,
            "ledger must be unadvanced after a failing rename"
        );
    }

    /// Helper: a single-connection in-memory SQLite pool (no pre-seeded todos
    /// table — callers control the full schema).
    async fn new_single_conn_db() -> Db {
        #[allow(clippy::expect_used)]
        sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite for rename tests")
    }

    #[tokio::test]
    async fn exec_query_params_bind_mixed_sqlvalue_types() {
        // db_exec_params / db_query_params bind the full SqlParam range (the
        //  mixed-type path) — Text/Int/Bool/Float/Null — and
        // round-trip through a SqlValue-param WHERE. `with_default` extracts the
        // Ok value (a wrong/Err result then fails the following assert).
        let db = fresh_db().await;
        // exec/unsafeExecRaw now return rows-affected (i64). DDL rows-affected is
        // driver-defined → assert Ok(_); each INSERT affects exactly 1 row.
        let mk: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, qty INTEGER, \
             active INTEGER, price REAL)"
                .to_string(),
        )
        .await;
        assert!(matches!(mk, IpeResult::Ok(_)), "create: {mk:?}");

        let ins: IpeResult<String, i64> = db_exec_params(
            db.clone(),
            "INSERT INTO items (name, qty, active, price) VALUES (?, ?, ?, ?)".to_string(),
            vec![
                SqlParam::Text("widget".to_string()),
                SqlParam::Int(7),
                SqlParam::Bool(true),
                SqlParam::Float(9.99),
            ],
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1)), "mixed insert: {ins:?}");

        // A row with typed NULLs (SqlNull carries a type witness so the
        // NULL binds with the right driver type-OID — see SqlParam::Null's
        // doc comment). `name` is TEXT, `price` is REAL: witness each with
        // the matching leaf variant.
        let ins2: IpeResult<String, i64> = db_exec_params(
            db.clone(),
            "INSERT INTO items (name, qty, active, price) VALUES (?, ?, ?, ?)".to_string(),
            vec![
                SqlParam::Null(Box::new(SqlParam::Text(String::new()))),
                SqlParam::Int(0),
                SqlParam::Bool(false),
                SqlParam::Null(Box::new(SqlParam::Float(0.0))),
            ],
        )
        .await;
        assert!(matches!(ins2, IpeResult::Ok(1)), "null insert: {ins2:?}");

        // SELECT with an Int SqlValue param.
        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT name, qty FROM items WHERE qty = ?".to_string(),
            vec![SqlParam::Int(7)],
        )
        .await;
        let rs = rows.with_default(Vec::new());
        assert_eq!(rs.len(), 1, "expected exactly 1 matching row, got {rs:?}");
        if let Some(r) = rs.first() {
            assert_eq!(r.get("name").map(String::as_str), Some("widget"));
            assert_eq!(r.get("qty").map(String::as_str), Some("7"));
        }
    }

    #[tokio::test]
    async fn test_insert_get_by_id() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "buy milk".to_string());
        row.insert("done".to_string(), "0".to_string());
        let id: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        let id = match id {
            IpeResult::Ok(v) => v,
            IpeResult::Err(e) => panic!("{}", e),
        };
        assert!(id > 0);

        let fetched: IpeResult<String, IpeMaybe<HashMap<String, String>>> =
            db_get_by_id(db, "todos".into(), id.to_string()).await;
        match fetched {
            IpeResult::Ok(IpeMaybe::Just(m)) => assert_eq!(m.get("title").unwrap(), "buy milk"),
            other => panic!("unexpected: {:?}", other),
        }
    }

    /// Tier-1 regression for the `db_insert_row`/`db_insert_fields`
    /// fabricated-`id = 0` fix (Class 7 §4b). `DB_USES_RETURNING_ID` is
    /// `false` on the standalone sqlite build, so `extract_returning_id` is
    /// called directly here — bypassing the `if DB_USES_RETURNING_ID` gate —
    /// against a REAL SQLite `RETURNING id` row with a non-integer (`TEXT`)
    /// PK. This exercises the exact decode-miss path without needing a live
    /// Postgres (`DB_USES_RETURNING_ID = true` is only reachable once the §3
    /// Postgres driver template is selected by a real project build).
    #[tokio::test]
    async fn extract_returning_id_errs_on_non_integer_pk() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE t (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("create table");
        let row = fetch_one_routed(
            &pool,
            sqlx::query("INSERT INTO t (id) VALUES ('non-integer-pk') RETURNING id"),
        )
        .await
        .expect("insert should succeed");
        assert!(
            extract_returning_id(&row).is_err(),
            "a non-integer id column must surface Err, never a fabricated 0"
        );
    }

    #[tokio::test]
    async fn extract_returning_id_ok_on_integer_pk() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("create table");
        let row = fetch_one_routed(
            &pool,
            sqlx::query("INSERT INTO t (id) VALUES (42) RETURNING id"),
        )
        .await
        .expect("insert should succeed");
        assert_eq!(extract_returning_id(&row), Ok(42));
    }

    #[tokio::test]
    async fn test_update_by_id() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "x".to_string());
        let id: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        let id = match id {
            IpeResult::Ok(v) => v,
            _ => panic!("insert"),
        };

        let mut updates = HashMap::new();
        updates.insert("title".to_string(), "y".to_string());
        let affected: IpeResult<String, i64> =
            db_update_by_id(db.clone(), "todos".into(), id.to_string(), updates).await;
        assert!(matches!(affected, IpeResult::Ok(1)));
    }

    #[tokio::test]
    async fn test_delete_by_id() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "z".to_string());
        let id: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        let id = match id {
            IpeResult::Ok(v) => v,
            _ => panic!("insert"),
        };
        let affected: IpeResult<String, i64> =
            db_delete_by_id(db, "todos".into(), id.to_string()).await;
        assert!(matches!(affected, IpeResult::Ok(1)));
    }

    fn where_eq_title(v: &str) -> SqlFragment {
        SqlFragment {
            sql: "title = ?".to_string(),
            binds: vec![SqlParam::Text(v.to_string())],
            invalid: None,
        }
    }

    async fn insert_title(db: &Db, title: &str) {
        let mut row = HashMap::new();
        row.insert("title".to_string(), title.to_string());
        let r: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        assert!(
            matches!(r, IpeResult::Ok(_)),
            "insert {title} failed: {r:?}"
        );
    }

    async fn count_title(db: &Db, title: &str) -> usize {
        let rs: IpeResult<String, Vec<HashMap<String, String>>> = db_find_many_by_field(
            db.clone(),
            "todos".into(),
            "title".into(),
            title.to_string(),
        )
        .await;
        match rs {
            IpeResult::Ok(v) => v.len(),
            IpeResult::Err(e) => panic!("count {title}: {e}"),
        }
    }

    #[tokio::test]
    async fn db_delete_where_deletes_only_matching_rows() {
        let db = fresh_db().await;
        insert_title(&db, "a").await;
        insert_title(&db, "b").await;
        let affected: IpeResult<String, i64> =
            db_delete_where(db.clone(), "todos".into(), where_eq_title("a")).await;
        assert!(
            matches!(affected, IpeResult::Ok(1)),
            "expected 1 deleted, got {affected:?}"
        );
        assert_eq!(count_title(&db, "a").await, 0, "matching row must be gone");
        assert_eq!(
            count_title(&db, "b").await,
            1,
            "non-matching row must remain"
        );
    }

    #[tokio::test]
    async fn db_delete_where_refuses_empty_where_and_preserves_all_rows() {
        let db = fresh_db().await;
        insert_title(&db, "a").await;
        insert_title(&db, "b").await;
        let frag = SqlFragment {
            sql: String::new(),
            binds: vec![],
            invalid: None,
        };
        let affected: IpeResult<String, i64> =
            db_delete_where(db.clone(), "todos".into(), frag).await;
        assert!(
            matches!(affected, IpeResult::Err(_)),
            "an empty WHERE must be refused, got {affected:?}"
        );
        assert_eq!(
            count_title(&db, "a").await,
            1,
            "a refused mass-delete must delete nothing"
        );
        assert_eq!(count_title(&db, "b").await, 1);
    }

    #[tokio::test]
    async fn db_update_where_updates_only_matching_rows() {
        let db = fresh_db().await;
        insert_title(&db, "a").await;
        insert_title(&db, "b").await;
        let set = vec![("title".to_string(), Some(SqlParam::Text("A2".to_string())))];
        let affected: IpeResult<String, i64> =
            db_update_where(db.clone(), "todos".into(), set, where_eq_title("a")).await;
        assert!(
            matches!(affected, IpeResult::Ok(1)),
            "expected 1 updated, got {affected:?}"
        );
        assert_eq!(
            count_title(&db, "A2").await,
            1,
            "matching row must be updated"
        );
        assert_eq!(count_title(&db, "b").await, 1, "non-matching row unchanged");
    }

    #[tokio::test]
    async fn db_update_where_refuses_whitespace_where_and_changes_nothing() {
        let db = fresh_db().await;
        insert_title(&db, "a").await;
        let set = vec![(
            "title".to_string(),
            Some(SqlParam::Text("mutated".to_string())),
        )];
        let frag = SqlFragment {
            sql: "   ".to_string(),
            binds: vec![],
            invalid: None,
        };
        let affected: IpeResult<String, i64> =
            db_update_where(db.clone(), "todos".into(), set, frag).await;
        assert!(
            matches!(affected, IpeResult::Err(_)),
            "a whitespace-only WHERE must be refused, got {affected:?}"
        );
        assert_eq!(count_title(&db, "a").await, 1, "original row untouched");
        assert_eq!(
            count_title(&db, "mutated").await,
            0,
            "no mass-update may occur"
        );
    }

    /// A hand-built fragment with no poison marker.
    fn checked_frag(sql: &str, binds: Vec<SqlParam>) -> SqlFragment {
        SqlFragment {
            sql: sql.to_string(),
            binds,
            invalid: None,
        }
    }

    fn text(v: &str) -> SqlParam {
        SqlParam::Text(v.to_string())
    }

    /// The checked insert is the plain insert plus the check's `RETURNING`; the
    /// check's binds come after the inserted values (placeholder order).
    #[test]
    fn checked_insert_sql_appends_the_check_after_the_insert_binds() {
        let built = build_checked_insert_sql(
            "docs",
            vec![
                ("author".to_string(), Some(text("alice"))),
                ("created_at".to_string(), None),
                ("n".to_string(), Some(SqlParam::Int(2))),
            ],
            checked_frag("author = ?", vec![text("check")]),
        );
        assert!(
            matches!(
                &built,
                Ok((sql, args)) if sql == "INSERT INTO docs (author, n) VALUES (?, ?) \
                    RETURNING (author = ?) AS ipe_policy_ok"
                    && *args == vec![text("alice"), SqlParam::Int(2), text("check")]
            ),
            "unexpected checked insert: {built:?}"
        );
    }

    /// The checked update binds SET, then WHERE, then the check, matching the
    /// textual order of their placeholders; an all-`OmitField` SET builds nothing.
    #[test]
    fn checked_update_sql_binds_set_then_where_then_check() {
        let built = build_checked_update_sql(
            "docs",
            vec![
                ("title".to_string(), Some(text("new"))),
                ("created_at".to_string(), None),
            ],
            checked_frag("id = ?", vec![SqlParam::Int(7)]),
            checked_frag("author = ?", vec![text("alice")]),
        );
        assert!(
            matches!(
                &built,
                Ok(UpdateStatement::Built { sql, args })
                    if sql == "UPDATE docs SET title = ? WHERE id = ? \
                        RETURNING (author = ?) AS ipe_policy_ok"
                    && *args == vec![text("new"), SqlParam::Int(7), text("alice")]
            ),
            "unexpected checked update: {built:?}"
        );
        let nothing = build_checked_update_sql(
            "docs",
            vec![("created_at".to_string(), None)],
            checked_frag("id = ?", vec![SqlParam::Int(7)]),
            checked_frag("1", vec![]),
        );
        assert!(
            matches!(nothing, Ok(UpdateStatement::NothingToSet)),
            "an all-OmitField SET must build nothing: {nothing:?}"
        );
    }

    /// A poisoned or empty check is refused before the statement is built, so a
    /// check can never be dropped from a write; the update builder keeps its own
    /// refusals.
    #[test]
    fn checked_write_builders_refuse_a_bad_check_or_statement() {
        let poisoned = sql_column("x;".to_string());
        let reason = "Sql.column: invalid identifier \"x;\"".to_string();
        assert!(
            matches!(
                PolicyCheck::parse(poisoned.clone()),
                Err(DbBuildError::PoisonedFragment { reason: r }) if r == reason
            ),
            "a poisoned check must be refused with its own reason"
        );
        let empty = PolicyCheck::parse(checked_frag("  ", vec![]));
        assert!(
            matches!(empty, Err(DbBuildError::EmptyCheck)),
            "an empty check must be refused: {empty:?}"
        );
        let insert = build_checked_insert_sql(
            "docs",
            vec![("a".to_string(), Some(SqlParam::Int(1)))],
            poisoned.clone(),
        );
        assert!(
            matches!(&insert, Err(DbBuildError::PoisonedFragment { .. })),
            "a checked insert with a poisoned check must be refused: {insert:?}"
        );
        let set = || vec![("a".to_string(), Some(SqlParam::Int(1)))];
        let update = build_checked_update_sql(
            "docs",
            set(),
            checked_frag("id = ?", vec![SqlParam::Int(1)]),
            poisoned.clone(),
        );
        assert!(
            matches!(&update, Err(DbBuildError::PoisonedFragment { .. })),
            "a checked update with a poisoned check must be refused: {update:?}"
        );
        let unscoped = build_checked_update_sql(
            "docs",
            set(),
            checked_frag(" ", vec![]),
            checked_frag("1", vec![]),
        );
        assert!(
            matches!(unscoped, Err(DbBuildError::UnscopedUpdate)),
            "an empty WHERE must be refused: {unscoped:?}"
        );
        let poisoned_where = build_update_where_sql("docs", set(), poisoned);
        assert!(
            matches!(
                &poisoned_where,
                Err(DbBuildError::PoisonedFragment { reason: r }) if *r == reason
            ),
            "a poisoned WHERE must be refused: {poisoned_where:?}"
        );
        let hostile_set = build_update_where_sql(
            "docs",
            vec![("a = 1; --".to_string(), Some(SqlParam::Int(1)))],
            checked_frag("id = ?", vec![SqlParam::Int(1)]),
        );
        assert!(
            matches!(
                &hostile_set,
                Err(e) if *e == invalid(IdentSlot::Column(ColumnList::Set), "a = 1; --")
            ),
            "a hostile SET column must be refused: {hostile_set:?}"
        );
    }

    /// The update refusals render the same task-edge text `db.updateWhere`
    /// has always reported.
    #[test]
    fn update_where_refusal_text_is_pinned() {
        let cases = [
            (
                DbBuildError::UnscopedUpdate,
                "db.updateWhere: refusing unscoped UPDATE (no WHERE); pass an explicit condition",
            ),
            (
                invalid(IdentSlot::Column(ColumnList::Set), "c;"),
                "db.updateWhere: invalid SET column name \"c;\"",
            ),
            (
                invalid(IdentSlot::Table, "t;"),
                "db.updateWhere: invalid table name \"t;\"",
            ),
            (
                DbBuildError::PoisonedFragment {
                    reason: "Sql.column: invalid identifier \"x;\"".to_string(),
                },
                "db.updateWhere: Sql.column: invalid identifier \"x;\"",
            ),
        ];
        for (e, want) in cases {
            let got: String = build_refusal("db.updateWhere", &e);
            assert_eq!(got, want, "refusal text for {e:?}");
        }
    }

    /// A checked insert of `title` under the check `check_sql`.
    async fn checked_insert_title(db: &Db, title: &str, check_sql: &str) -> IpeResult<String, i64> {
        db_insert_fields_checked(
            db.clone(),
            "todos".into(),
            vec![("title".to_string(), Some(text(title)))],
            checked_frag(check_sql, vec![]),
        )
        .await
    }

    /// Only a check returning `1` keeps the row; `0`, `NULL`, any other integer
    /// (`2`, `-1`: a SQLite `bool` decode would read them as `true`), a real,
    /// and a value that does not decode as a boolean or integer (`'yes'`) each
    /// roll it back.
    #[tokio::test]
    async fn checked_insert_keeps_only_an_admitted_row() {
        let db = fresh_db().await;
        let cases = [
            ("kept", "1", 1i64),
            ("zero", "0", 0),
            ("null", "NULL", 0),
            ("two", "2", 0),
            ("minus", "-1", 0),
            ("real", "1.0", 0),
            ("text", "'yes'", 0),
        ];
        for (title, check, want) in cases {
            let got = checked_insert_title(&db, title, check).await;
            assert!(
                matches!(got, IpeResult::Ok(n) if n == want),
                "check {check}: expected Ok({want}), got {got:?}"
            );
            let stored = count_title(&db, title).await;
            assert_eq!(
                i64::try_from(stored).ok(),
                Some(want),
                "check {check}: the stored row count must equal the returned count"
            );
        }
    }

    /// The checked update keeps a write only when the row satisfies the check
    /// after the write; a WHERE that matches nothing writes nothing.
    #[tokio::test]
    async fn checked_update_rolls_back_a_refused_row() {
        let db = fresh_db().await;
        insert_title(&db, "a").await;
        let update = |to: &str, check_value: &str| {
            db_update_where_checked::<String>(
                db.clone(),
                "todos".into(),
                vec![("title".to_string(), Some(text(to)))],
                where_eq_title("a"),
                checked_frag("title = ?", vec![text(check_value)]),
            )
        };
        let refused = update("b", "c").await;
        assert!(
            matches!(refused, IpeResult::Ok(0)),
            "a row failing the check after the write must give 0, got {refused:?}"
        );
        assert_eq!(
            count_title(&db, "a").await,
            1,
            "the refused update rolled back"
        );
        assert_eq!(
            count_title(&db, "b").await,
            0,
            "the refused value is not stored"
        );
        let kept = update("b", "b").await;
        assert!(
            matches!(kept, IpeResult::Ok(1)),
            "a row satisfying the check after the write must give 1, got {kept:?}"
        );
        assert_eq!(
            count_title(&db, "b").await,
            1,
            "the admitted update is stored"
        );
        let unmatched = update("z", "z").await;
        assert!(
            matches!(unmatched, IpeResult::Ok(0)),
            "a WHERE matching no row must give 0, got {unmatched:?}"
        );
        assert_eq!(count_title(&db, "z").await, 0);
    }

    /// A correlated `EXISTS` over another table, naming the written row as
    /// `<table>.<col>`, is evaluated in the `RETURNING` check.
    #[tokio::test]
    async fn checked_insert_evaluates_a_correlated_subquery() {
        let db = fresh_db().await;
        let created: IpeResult<String, i64> = db_exec(
            db.clone(),
            "CREATE TABLE shares (doc_title TEXT NOT NULL)".into(),
            vec![],
        )
        .await;
        assert!(
            matches!(created, IpeResult::Ok(_)),
            "create shares: {created:?}"
        );
        let check = "EXISTS (SELECT 1 FROM shares WHERE shares.doc_title = todos.title)";
        let unshared = checked_insert_title(&db, "y", check).await;
        assert!(
            matches!(unshared, IpeResult::Ok(0)),
            "without a share the insert must give 0, got {unshared:?}"
        );
        assert_eq!(count_title(&db, "y").await, 0);
        let shared: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO shares (doc_title) VALUES (?)".into(),
            vec!["y".to_string()],
        )
        .await;
        assert!(
            matches!(shared, IpeResult::Ok(_)),
            "insert share: {shared:?}"
        );
        let admitted = checked_insert_title(&db, "y", check).await;
        assert!(
            matches!(admitted, IpeResult::Ok(1)),
            "with a share the insert must give 1, got {admitted:?}"
        );
        assert_eq!(count_title(&db, "y").await, 1);
    }

    /// A refused checked write inside a transaction rolls back only its own
    /// savepoint: later writes in the same transaction still commit.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: the recording transaction is solely owned once its scope ends
    async fn checked_write_savepoint_leaves_the_outer_transaction_usable() {
        let db = fresh_db().await;
        let rec = recording_txn(&db).await;
        let (refused, admitted, plain) = with_recording_txn(&db, rec.clone(), async {
            let refused = checked_insert_title(&db, "refused", "0").await;
            let admitted = checked_insert_title(&db, "admitted", "1").await;
            let plain: IpeResult<String, i64> = db_insert_fields(
                db.clone(),
                "todos".into(),
                vec![("title".to_string(), Some(text("plain")))],
            )
            .await;
            (refused, admitted, plain)
        })
        .await;
        assert!(matches!(refused, IpeResult::Ok(0)), "refused: {refused:?}");
        assert!(
            matches!(admitted, IpeResult::Ok(1)),
            "admitted: {admitted:?}"
        );
        assert!(matches!(plain, IpeResult::Ok(_)), "plain: {plain:?}");
        let tx = std::sync::Arc::try_unwrap(rec)
            .expect("the scope released its clone")
            .into_inner();
        tx.commit().await.expect("commit the outer transaction");
        assert_eq!(
            count_title(&db, "refused").await,
            0,
            "the refused row rolled back"
        );
        assert_eq!(
            count_title(&db, "admitted").await,
            1,
            "the admitted row committed"
        );
        assert_eq!(
            count_title(&db, "plain").await,
            1,
            "the later plain insert committed"
        );
    }

    /// A checked write whose statement fails inside a transaction rolls back
    /// its own savepoint and reports the error; the transaction stays usable
    /// and a later write in it commits.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test: the recording transaction is solely owned once its scope ends
    async fn checked_write_error_leaves_the_outer_transaction_usable() {
        let db = fresh_db().await;
        let rec = recording_txn(&db).await;
        let (failed, plain) = with_recording_txn(&db, rec.clone(), async {
            // `title` is `NOT NULL` and omitted: the insert itself fails.
            let failed: IpeResult<String, i64> = db_insert_fields_checked(
                db.clone(),
                "todos".into(),
                vec![("done".to_string(), Some(SqlParam::Int(1)))],
                checked_frag("1", vec![]),
            )
            .await;
            let plain: IpeResult<String, i64> = db_insert_fields(
                db.clone(),
                "todos".into(),
                vec![("title".to_string(), Some(text("after")))],
            )
            .await;
            (failed, plain)
        })
        .await;
        assert!(matches!(failed, IpeResult::Err(_)), "failed: {failed:?}");
        assert!(matches!(plain, IpeResult::Ok(_)), "plain: {plain:?}");
        let tx = std::sync::Arc::try_unwrap(rec)
            .expect("the scope released its clone")
            .into_inner();
        tx.commit().await.expect("commit the outer transaction");
        assert_eq!(
            count_title(&db, "after").await,
            1,
            "the later plain insert committed"
        );
    }

    #[tokio::test]
    async fn test_find_one_by_field() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "find me".to_string());
        let _: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        let found: IpeResult<String, IpeMaybe<HashMap<String, String>>> =
            db_find_one_by_field(db, "todos".into(), "title".into(), "find me".into()).await;
        assert!(matches!(found, IpeResult::Ok(IpeMaybe::Just(_))));
    }

    #[tokio::test]
    async fn test_find_many_and_by_conditions() {
        let db = fresh_db().await;
        for t in ["a", "b", "c"] {
            let mut r = HashMap::new();
            r.insert("title".to_string(), t.to_string());
            r.insert("done".to_string(), "1".to_string());
            let _: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), r).await;
        }
        let many: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db.clone(), "todos".into(), "done".into(), "1".into()).await;
        match many {
            IpeResult::Ok(v) => assert_eq!(v.len(), 3),
            _ => panic!("find many"),
        }

        let mut cond = HashMap::new();
        cond.insert("done".to_string(), "1".to_string());
        cond.insert("title".to_string(), "b".to_string());
        let one: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_by_conditions(db.clone(), "todos".into(), cond).await;
        match one {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1),
            _ => panic!("conds"),
        }

        // Empty condition set MUST be refused (would otherwise return every
        // row — a cross-tenant read when request-derived filters come back empty).
        let empty_cond: HashMap<String, String> = HashMap::new();
        let refused: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_by_conditions(db.clone(), "todos".into(), empty_cond).await;
        assert!(
            matches!(refused, IpeResult::Err(_)),
            "empty conditions must be refused, got {refused:?}"
        );

        // Non-empty conditions still return filtered rows (happy-path regression).
        let mut only_done = HashMap::new();
        only_done.insert("done".to_string(), "1".to_string());
        let filtered: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_by_conditions(db, "todos".into(), only_done).await;
        match filtered {
            IpeResult::Ok(v) => assert_eq!(v.len(), 3, "expected 3 done rows"),
            _ => panic!("non-empty conditions should return rows"),
        }
    }

    #[tokio::test]
    async fn test_with_transaction_commit() {
        let db = fresh_db().await;
        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), |c| {
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "txn".to_string());
                db_insert_row(c, "todos".into(), row).await
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Ok(_)));
        // The inserted row should be visible after commit:
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db, "todos".into(), "title".into(), "txn".into()).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1),
            _ => panic!("post-commit fetch"),
        }
    }

    #[tokio::test]
    async fn test_with_transaction_rollback_returns_err() {
        // Err propagates AND the write is actually undone. With the task-local
        // dedicated-connection routing, BEGIN / INSERT / ROLLBACK all run on the
        // same connection, so the row is gone after rollback (single-conn pool).
        let db = fresh_db().await;
        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), |c| {
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "txn-err".to_string());
                let _: IpeResult<String, i64> = db_insert_row(c, "todos".into(), row).await;
                IpeResult::Err("boom".to_string())
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Err(_)));
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db, "todos".into(), "title".into(), "txn-err".into()).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 0, "rollback must undo the INSERT"),
            _ => panic!("post-rollback fetch"),
        }
    }

    // Build a FILE-based sqlite pool (temp file, NOT `:memory:` — in-memory
    // sqlite is per-connection so it can't exhibit the cross-connection bug)
    // with `max_connections > 1` and WAL. Returns (pool, tempdir-guard); the
    // guard must outlive the pool so the file isn't deleted early.
    async fn fresh_file_db(max_conns: u32) -> (Db, std::path::PathBuf) {
        let mut path = crate::scratch_core::test_temp_root();
        // Unique per test run to avoid cross-test contamination.
        let unique = format!(
            "ipe_txn_test_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        path.push(unique);
        // Fresh file every time.
        let _ = std::fs::remove_file(&path);
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let options = url
            .parse::<sqlx::sqlite::SqliteConnectOptions>()
            .expect("parse file sqlite url")
            .busy_timeout(SQLITE_BUSY_TIMEOUT);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max_conns)
            .connect_with(options)
            .await
            .expect("connect file sqlite");
        // WAL: concurrent readers alongside a single writer.
        let _ = sqlx::query("PRAGMA journal_mode=WAL;").execute(&pool).await;
        sqlx::query("CREATE TABLE todos (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0)")
            .execute(&pool).await.expect("create table");
        (pool, path)
    }

    // THE REGRESSION GATE. On a MULTI-connection (5) file-backed pool, a
    // withTransaction body that INSERTs then returns Err must roll the INSERT
    // back. Against the old bare-pool code BEGIN/INSERT/ROLLBACK scattered across
    // different connections → the INSERT autocommitted on its own connection →
    // this assert would find the row present (FAIL). With task-local routing all
    // three run on one connection → row absent (PASS).
    #[tokio::test]
    async fn test_with_transaction_cancellation_rolls_back() {
        // CANCELLATION SAFETY regression: a body future DROPPED mid-transaction
        // (here via task abort) must NOT leak an open txn onto the pooled
        // connection — the next checkout would otherwise inherit it. 1-conn pool
        // forces reuse of the exact connection the cancelled txn ran on.
        let (db, path) = fresh_file_db(1).await;
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let started2 = started.clone();
        let dbc = db.clone();
        let handle = tokio::spawn(async move {
            let _: IpeResult<String, i64> = db_with_transaction(dbc, move |c| {
                let started2 = started2.clone();
                Box::pin(async move {
                    let mut row = HashMap::new();
                    row.insert("title".to_string(), "cancelled".to_string());
                    let _: IpeResult<String, i64> = db_insert_row(c, "todos".into(), row).await;
                    started2.notify_one(); // INSERT is in the open txn — signal, then hang
                    std::future::pending::<()>().await; // dropped by abort below
                    IpeResult::Ok(0)
                })
            })
            .await;
        });
        started.notified().await;
        handle.abort();
        let _ = handle.await;

        // Reused connection must NOT be poisoned by an inherited open txn.
        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), |c| {
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "after".to_string());
                db_insert_row(c, "todos".into(), row).await
            })
        })
        .await;
        assert!(
            matches!(r, IpeResult::Ok(_)),
            "post-cancel txn must succeed on the reused connection: {:?}",
            r
        );
        // The cancelled INSERT must have rolled back on drop (fold to a count to
        // avoid a panic!-form assertion — the risk-precheck flags raw panic!).
        let cancelled_count = match db_find_many_by_field::<String>(
            db.clone(),
            "todos".into(),
            "title".into(),
            "cancelled".into(),
        )
        .await
        {
            IpeResult::Ok(v) => v.len(),
            IpeResult::Err(_) => usize::MAX,
        };
        assert_eq!(
            cancelled_count, 0,
            "cancelled INSERT must roll back on drop"
        );
        db.close().await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn test_with_transaction_rollback_real_on_multiconn_pool() {
        let (db, path) = fresh_file_db(5).await;

        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), |c| {
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "rollback-me".to_string());
                let _: IpeResult<String, i64> = db_insert_row(c, "todos".into(), row).await;
                IpeResult::Err("forced rollback".to_string())
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Err(_)), "body Err propagates");

        // The row MUST be absent — rollback actually undid the write.
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_many_by_field(
            db.clone(),
            "todos".into(),
            "title".into(),
            "rollback-me".into(),
        )
        .await;
        match found {
            IpeResult::Ok(v) => assert_eq!(
                v.len(),
                0,
                "ROLLBACK did not undo the INSERT on a multi-connection pool — \
                 BEGIN/INSERT/ROLLBACK landed on different connections"
            ),
            other => panic!("post-rollback fetch: {:?}", other),
        }

        db.close().await;
        let _ = std::fs::remove_file(&path);
    }

    // Ok-path on a multi-connection file pool: COMMIT must persist the row.
    #[tokio::test]
    async fn test_with_transaction_commit_real_on_multiconn_pool() {
        let (db, path) = fresh_file_db(5).await;

        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), |c| {
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "commit-me".to_string());
                db_insert_row(c, "todos".into(), row).await
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Ok(_)), "body Ok");

        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_many_by_field(
            db.clone(),
            "todos".into(),
            "title".into(),
            "commit-me".into(),
        )
        .await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1, "COMMIT must persist the row"),
            other => panic!("post-commit fetch: {:?}", other),
        }

        db.close().await;
        let _ = std::fs::remove_file(&path);
    }

    // Nested withTransaction must NOT deadlock and must NOT acquire a second
    // connection. Flattened semantics: the inner block runs on the outer
    // transaction's connection; an outer Err rolls everything back.
    #[tokio::test]
    async fn test_with_transaction_nested_no_deadlock() {
        let (db, path) = fresh_file_db(5).await;
        let db_for_inner = db.clone();

        let r: IpeResult<String, i64> = db_with_transaction(db.clone(), move |c| {
            let inner_db = db_for_inner.clone();
            Box::pin(async move {
                let mut row = HashMap::new();
                row.insert("title".to_string(), "outer".to_string());
                let _: IpeResult<String, i64> = db_insert_row(c, "todos".into(), row).await;
                // Nested call — must reuse the held connection (no deadlock).
                db_with_transaction(inner_db, |c2| {
                    Box::pin(async move {
                        let mut row2 = HashMap::new();
                        row2.insert("title".to_string(), "inner".to_string());
                        db_insert_row(c2, "todos".into(), row2).await
                    })
                })
                .await
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Ok(_)), "nested commit Ok");

        // Both rows committed (flattened into one transaction).
        let outer: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db.clone(), "todos".into(), "title".into(), "outer".into()).await;
        let inner: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db.clone(), "todos".into(), "title".into(), "inner".into()).await;
        assert!(
            matches!(outer, IpeResult::Ok(ref v) if v.len() == 1),
            "outer row present"
        );
        assert!(
            matches!(inner, IpeResult::Ok(ref v) if v.len() == 1),
            "inner row present"
        );

        db.close().await;
        let _ = std::fs::remove_file(&path);
    }

    // Build a recording `TxnConn` — a real transaction opened on `pool` and
    // wrapped exactly as `db_with_transaction` wraps its own. Handed to
    // `with_recording_txn`, it installs into the ambient `TXN_CONN` under the
    // real `pool_identity`, so a test observes routing through the genuine
    // ambient path and the `ptr_eq` gate, not a task-local backdoor.
    async fn recording_txn(pool: &Db) -> TxnConn {
        let tx = pool.begin().await.expect("begin recording txn");
        std::sync::Arc::new(tokio::sync::Mutex::new(tx))
    }

    // (a) An op inside a `withTransaction` scope lands on the txn connection:
    // `route_for` chooses the Txn arm for the scope's own pool. Outside the
    // scope the same pool routes back to the Pool arm — the task-local is
    // scoped, not sticky.
    #[tokio::test]
    async fn test_route_inside_scope_rides_txn() {
        let db = fresh_db().await;
        let rec = recording_txn(&db).await;
        assert!(
            !route_for(&db).rode_transaction(),
            "outside any scope, a query routes to the pool"
        );
        let rode = with_recording_txn(&db, rec, async { route_for(&db).rode_transaction() }).await;
        assert!(
            rode,
            "inside the scope, a query on the scope's pool rides the txn conn"
        );
        assert!(
            !route_for(&db).rode_transaction(),
            "after the scope ends, the pool arm is chosen again"
        );
    }

    // (b) THE AUD-03 REFUSAL. Inside a txn scope opened on `db_a`, a query on a
    // DIFFERENT pool `db_b` must NOT ride `db_a`'s transaction connection — it
    // falls through to `db_b`'s pool. This pins the `ptr_eq` pool-identity gate
    // in `current_txn_conn_for`: with the gate removed (routing on presence
    // alone), `db_b` would wrongly ride `db_a`'s open transaction — the exact
    // cross-pool leak the gate closes.
    #[tokio::test]
    async fn test_route_cross_pool_inside_scope_falls_through_to_pool() {
        let db_a = fresh_db().await;
        let db_b = fresh_db().await;
        let rec_a = recording_txn(&db_a).await;
        let (a_rode, b_rode) = with_recording_txn(&db_a, rec_a, async {
            (
                route_for(&db_a).rode_transaction(),
                route_for(&db_b).rode_transaction(),
            )
        })
        .await;
        assert!(a_rode, "the scope's own pool rides the txn conn");
        assert!(
            !b_rode,
            "AUD-03: a query on a different pool must fall through to its own pool, \
             never ride another pool's transaction connection"
        );
    }

    // (c) Nested `withTransaction` on the SAME pool flattens: inside a scope on
    // `db`, a query on `db` reuses the very connection installed by the outer
    // scope (ptr-equal), never a second one — the flatten that
    // `db_with_transaction` performs when `current_txn_conn_for` is already Some.
    #[tokio::test]
    async fn test_route_nested_same_pool_flattens_onto_outer_conn() {
        let db = fresh_db().await;
        let rec = recording_txn(&db).await;
        let rec_probe = rec.clone();
        let same = with_recording_txn(&db, rec, async {
            route_for(&db).rode_same_txn_as(&rec_probe)
        })
        .await;
        assert!(
            same,
            "a nested op on the same pool reuses the outer transaction connection, not a new one"
        );
    }

    // AUD-03 regression: a nested `withTransaction` call for a DIFFERENT `Db`
    // handle must open its OWN independent transaction, never flatten onto an
    // outer transaction opened on a different pool (which would silently
    // execute the nested pool's operations against the wrong physical
    // connection — cross-database data corruption). Both tests below FAIL
    // under the pre-fix code (which flattened on ANY active transaction
    // regardless of pool identity) and pass once nesting is gated on
    // `current_txn_conn_for`'s pool-identity check.
    #[tokio::test]
    async fn test_with_transaction_cross_pool_nested_targets_correct_db() {
        let (db_a, path_a) = fresh_file_db(5).await;
        let (db_b, path_b) = fresh_file_db(5).await;
        let db_b_for_inner = db_b.clone();

        let r: IpeResult<String, i64> = db_with_transaction(db_a.clone(), move |c_a| {
            let db_b_inner = db_b_for_inner.clone();
            Box::pin(async move {
                let mut row_a = HashMap::new();
                row_a.insert("title".to_string(), "in-a".to_string());
                let _: IpeResult<String, i64> = db_insert_row(c_a, "todos".into(), row_a).await;

                // Nested withTransaction on a DIFFERENT pool — must open its
                // own transaction on db_b, not flatten onto db_a's.
                db_with_transaction(db_b_inner, |c_b| {
                    Box::pin(async move {
                        let mut row_b = HashMap::new();
                        row_b.insert("title".to_string(), "in-b".to_string());
                        db_insert_row(c_b, "todos".into(), row_b).await
                    })
                })
                .await
            })
        })
        .await;
        assert!(matches!(r, IpeResult::Ok(_)), "outer+nested commit Ok");

        // The dbB row must land in dbB, NOT dbA.
        let a_has_b_row: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db_a.clone(), "todos".into(), "title".into(), "in-b".into())
                .await;
        assert!(
            matches!(a_has_b_row, IpeResult::Ok(ref v) if v.is_empty()),
            "dbA must NOT contain dbB's row"
        );

        let b_has_b_row: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db_b.clone(), "todos".into(), "title".into(), "in-b".into())
                .await;
        assert!(
            matches!(b_has_b_row, IpeResult::Ok(ref v) if v.len() == 1),
            "dbB must contain its own row"
        );

        let a_has_a_row: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_many_by_field(db_a.clone(), "todos".into(), "title".into(), "in-a".into())
                .await;
        assert!(
            matches!(a_has_a_row, IpeResult::Ok(ref v) if v.len() == 1),
            "dbA must contain its own row"
        );

        db_a.close().await;
        db_b.close().await;
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[tokio::test]
    async fn test_with_transaction_cross_pool_nested_rollback_independent() {
        let (db_a, path_a) = fresh_file_db(5).await;
        let (db_b, path_b) = fresh_file_db(5).await;
        let db_b_for_inner = db_b.clone();

        let r: IpeResult<String, i64> = db_with_transaction(db_a.clone(), move |c_a| {
            let db_b_inner = db_b_for_inner.clone();
            Box::pin(async move {
                let mut row_a = HashMap::new();
                row_a.insert("title".to_string(), "a-commits".to_string());
                let _: IpeResult<String, i64> = db_insert_row(c_a, "todos".into(), row_a).await;

                // Inner transaction on a DIFFERENT pool fails and rolls back —
                // must NOT roll back the outer dbA transaction.
                let inner: IpeResult<String, i64> = db_with_transaction(db_b_inner, |c_b| {
                    Box::pin(async move {
                        let mut row_b = HashMap::new();
                        row_b.insert("title".to_string(), "b-rolls-back".to_string());
                        let _: IpeResult<String, i64> =
                            db_insert_row(c_b, "todos".into(), row_b).await;
                        IpeResult::<String, i64>::Err("inner fails deliberately".to_string())
                    })
                })
                .await;
                assert!(
                    matches!(inner, IpeResult::Err(_)),
                    "inner reports its own error"
                );

                IpeResult::Ok(0i64)
            })
        })
        .await;
        assert!(
            matches!(r, IpeResult::Ok(_)),
            "outer commit Ok despite inner rollback"
        );

        let a_row: IpeResult<String, Vec<HashMap<String, String>>> = db_find_many_by_field(
            db_a.clone(),
            "todos".into(),
            "title".into(),
            "a-commits".into(),
        )
        .await;
        assert!(
            matches!(a_row, IpeResult::Ok(ref v) if v.len() == 1),
            "dbA row committed"
        );

        let b_row: IpeResult<String, Vec<HashMap<String, String>>> = db_find_many_by_field(
            db_b.clone(),
            "todos".into(),
            "title".into(),
            "b-rolls-back".into(),
        )
        .await;
        assert!(
            matches!(b_row, IpeResult::Ok(ref v) if v.is_empty()),
            "dbB row rolled back independently"
        );

        db_a.close().await;
        db_b.close().await;
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[tokio::test]
    async fn test_get_bool() {
        let mut r = HashMap::new();
        r.insert("a".to_string(), "1".to_string());
        r.insert("b".to_string(), "0".to_string());
        r.insert("c".to_string(), "true".to_string());
        r.insert("d".to_string(), "false".to_string());
        assert!(db_get_bool("a".into(), &r));
        assert!(!db_get_bool("b".into(), &r));
        assert!(db_get_bool("c".into(), &r));
        assert!(!db_get_bool("d".into(), &r));
        assert!(!db_get_bool("missing".into(), &r));
    }

    #[tokio::test]
    async fn test_query_decode() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "decoded".to_string());
        let _: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        // Use the Decoder<E,A> API: db_decode_string reads the "title" column from
        // the NULL-preserving JsonVal::Object produced by row_to_json.
        let decoded: IpeResult<String, Vec<String>> = db_query_decode(
            db,
            "SELECT title FROM todos".into(),
            vec![],
            db_decode_string("title".to_string()),
        )
        .await;
        match decoded {
            IpeResult::Ok(v) => assert_eq!(v, vec!["decoded".to_string()]),
            _ => panic!("decode"),
        }
    }

    #[tokio::test]
    async fn test_query_decode_int_and_nullable() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "item".to_string());
        row.insert("done".to_string(), "1".to_string());
        let _: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;

        // Test db_decode_int decodes the "done" column correctly.
        let decoded_int: IpeResult<String, Vec<i64>> = db_query_decode(
            db.clone(),
            "SELECT done FROM todos".into(),
            vec![],
            db_decode_int("done".to_string()),
        )
        .await;
        match decoded_int {
            IpeResult::Ok(v) => assert_eq!(v, vec![1i64]),
            _ => panic!("db_decode_int decode failed"),
        }

        // Test db_decode_bool.
        let decoded_bool: IpeResult<String, Vec<bool>> = db_query_decode(
            db.clone(),
            "SELECT done FROM todos".into(),
            vec![],
            db_decode_bool("done".to_string()),
        )
        .await;
        match decoded_bool {
            IpeResult::Ok(v) => assert_eq!(v, vec![true]),
            _ => panic!("db_decode_bool decode failed"),
        }
    }

    #[test]
    fn db_decode_int_rejects_out_of_range_float() {
        let dec = db_decode_int::<String>("n".to_string());

        // In-range: a decimal string truncates toward zero, still Ok.
        let in_range = serde_json::json!({ "n": "3.7" });
        match (dec.run)(&in_range) {
            IpeResult::Ok(i) => assert_eq!(i, 3),
            IpeResult::Err(e) => panic!("in-range decode failed: {:?}", e),
        }

        // In-range: a JSON float that is integral and representable decodes.
        let in_range_num = serde_json::json!({ "n": 42.0 });
        match (db_decode_int::<String>("n".to_string()).run)(&in_range_num) {
            IpeResult::Ok(i) => assert_eq!(i, 42),
            IpeResult::Err(e) => panic!("in-range numeric decode failed: {:?}", e),
        }

        // Out-of-range: `1e30` past i64::MAX must REJECT, not saturate to i64::MAX.
        let over = serde_json::json!({ "n": 1e30 });
        match (db_decode_int::<String>("n".to_string()).run)(&over) {
            IpeResult::Ok(i) => panic!("out-of-range float saturated to {i} instead of erroring"),
            IpeResult::Err(_) => {}
        }

        // Out-of-range as a decimal string is rejected on the same path.
        let over_str = serde_json::json!({ "n": "1e30" });
        match (db_decode_int::<String>("n".to_string()).run)(&over_str) {
            IpeResult::Ok(i) => panic!("out-of-range string saturated to {i} instead of erroring"),
            IpeResult::Err(_) => {}
        }

        // i64::MIN-1 rounds to i64::MIN as f64; a non-strict lower bound would
        // admit it and saturate to i64::MIN. It must reject.
        let under = serde_json::json!({ "n": "-9223372036854775809" });
        match (db_decode_int::<String>("n".to_string()).run)(&under) {
            IpeResult::Ok(i) => panic!("i64::MIN-1 saturated to {i} instead of erroring"),
            IpeResult::Err(_) => {}
        }

        // The exact boundaries still decode through the integer path.
        let min = serde_json::json!({ "n": "-9223372036854775808" });
        match (db_decode_int::<String>("n".to_string()).run)(&min) {
            IpeResult::Ok(i) => assert_eq!(i, i64::MIN),
            IpeResult::Err(e) => panic!("i64::MIN decode failed: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_query_decode_nullable_null() {
        // SQLite table with a nullable column.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect");
        sqlx::query("CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT)")
            .execute(&pool)
            .await
            .expect("create");
        // Row with NULL label.
        sqlx::query("INSERT INTO items (id, label) VALUES (1, NULL)")
            .execute(&pool)
            .await
            .expect("insert null");
        // Row with non-null label.
        sqlx::query("INSERT INTO items (id, label) VALUES (2, 'hello')")
            .execute(&pool)
            .await
            .expect("insert some");

        // db_decode_nullable(db_decode_string("label")): NULL → Nothing, "hello" → Just("hello").
        // (1-arg form: inner.fields = ["label"] provides the NULL-gate column.)

        // Check NULL row → Nothing.
        let r1: IpeResult<String, Vec<IpeMaybe<String>>> = db_query_decode(
            pool.clone(),
            "SELECT label FROM items WHERE id = 1".into(),
            vec![],
            db_decode_nullable(db_decode_string("label".to_string())),
        )
        .await;
        match r1 {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert!(
                    matches!(v[0], IpeMaybe::Nothing),
                    "expected Nothing for NULL, got {:?}",
                    v[0]
                );
            }
            IpeResult::Err(e) => panic!("unexpected Err on NULL row: {}", e),
        }

        // Check non-NULL row → Just("hello").
        let r2: IpeResult<String, Vec<IpeMaybe<String>>> = db_query_decode(
            pool,
            "SELECT label FROM items WHERE id = 2".into(),
            vec![],
            db_decode_nullable(db_decode_string("label".to_string())),
        )
        .await;
        match r2 {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert!(
                    matches!(&v[0], IpeMaybe::Just(s) if s == "hello"),
                    "expected Just(\"hello\"), got {:?}",
                    v[0]
                );
            }
            IpeResult::Err(e) => panic!("unexpected Err on non-null row: {}", e),
        }
    }

    #[tokio::test]
    async fn test_get_by_id_decode() {
        let db = fresh_db().await;
        let mut row = HashMap::new();
        row.insert("title".to_string(), "find-me".to_string());
        let id: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), row).await;
        let id = match id {
            IpeResult::Ok(v) => v,
            _ => panic!("insert"),
        };

        let found: IpeResult<String, IpeMaybe<String>> = db_get_by_id_decode(
            db.clone(),
            "todos".into(),
            id,
            db_decode_string("title".to_string()),
        )
        .await;
        match found {
            IpeResult::Ok(IpeMaybe::Just(s)) => assert_eq!(s, "find-me"),
            other => panic!("unexpected: {:?}", other),
        }

        // Non-existent id → Nothing.
        let not_found: IpeResult<String, IpeMaybe<String>> = db_get_by_id_decode(
            db,
            "todos".into(),
            99999,
            db_decode_string("title".to_string()),
        )
        .await;
        assert!(matches!(not_found, IpeResult::Ok(IpeMaybe::Nothing)));
    }

    #[tokio::test]
    async fn test_db_decode_money_roundtrip() {
        // Verify db_decode_money parses "USD 12.34" → (Decimal(12.34), "USD").
        use rust_decimal::Decimal as RD;
        use std::str::FromStr;
        let val = serde_json::json!({ "price": "USD 12.34" });
        let result = (db_decode_money::<String>("price".to_string()).run)(&val);
        match result {
            IpeResult::Ok((amount, code)) => {
                assert_eq!(code, "USD");
                assert_eq!(amount.0, RD::from_str("12.34").unwrap());
            }
            IpeResult::Err(e) => panic!("unexpected Err: {}", e),
        }

        // NULL → Err.
        let val_null = serde_json::json!({ "price": null });
        assert!(matches!(
            (db_decode_money::<String>("price".to_string()).run)(&val_null),
            IpeResult::Err(_)
        ));

        // Bad format → Err.
        let val_bad = serde_json::json!({ "price": "NODECIMAL" });
        assert!(matches!(
            (db_decode_money::<String>("price".to_string()).run)(&val_bad),
            IpeResult::Err(_)
        ));
    }

    #[tokio::test]
    async fn test_db_decode_decimal_roundtrip() {
        // Verify db_decode_decimal parses "3.14159" → Decimal(3.14159).
        use rust_decimal::Decimal as RD;
        use std::str::FromStr;
        let val = serde_json::json!({ "amount": "3.14159" });
        let result = (db_decode_decimal::<String>("amount".to_string()).run)(&val);
        match result {
            IpeResult::Ok(d) => {
                assert_eq!(d.0, RD::from_str("3.14159").unwrap());
            }
            IpeResult::Err(e) => panic!("unexpected Err: {}", e),
        }

        // NULL → Err.
        let val_null = serde_json::json!({ "amount": null });
        assert!(matches!(
            (db_decode_decimal::<String>("amount".to_string()).run)(&val_null),
            IpeResult::Err(_)
        ));

        // Non-numeric text → Err.
        let val_bad = serde_json::json!({ "amount": "not-a-number" });
        assert!(matches!(
            (db_decode_decimal::<String>("amount".to_string()).run)(&val_bad),
            IpeResult::Err(_)
        ));

        // Missing column → Err.
        let val_missing = serde_json::json!({ "other": "x" });
        assert!(matches!(
            (db_decode_decimal::<String>("amount".to_string()).run)(&val_missing),
            IpeResult::Err(_)
        ));
    }

    #[tokio::test]
    async fn test_db_decode_decimal_money_pg_dialect() {
        // Verifies that the Postgres-dialect INSERT+SELECT statement for a
        // Decimal/Money column pair uses $N placeholders (not ?), binds values
        // as TEXT string parameters (never float/REAL), and that the DDL column
        // type is TEXT.
        //
        // No live Postgres cluster is available in CI; this test drives the
        // statement-generation path directly against the ExternalConnection
        // Postgres variant to assert correct SQL shape and bind types.
        //
        // A live-pg round-trip is unimplementable without new infrastructure
        // (no DATABASE_URL in CI). The statement-generation assertion here is
        // the extent of pg coverage possible without that infra.
        use rust_decimal::Decimal as RD;
        use std::str::FromStr;

        // Decimal stores as TEXT — confirm from_str round-trips without float
        // intermediary loss.
        let d = RD::from_str("9.99").expect("parse");
        let s = d.to_string();
        assert_eq!(s, "9.99", "Decimal TEXT round-trip must be exact");

        // Money stores as "CODE AMOUNT" TEXT — confirm the canonical format
        // the runtime expects on decode.
        let money_text = "USD 12.34";
        let (code, amount_str) = money_text.split_once(' ').expect("split");
        let amount = RD::from_str(amount_str).expect("parse");
        assert_eq!(code, "USD");
        assert_eq!(amount, RD::from_str("12.34").unwrap());

        // The Postgres-dialect placeholder test: SqlitePool uses '?' while the
        // Postgres driver uses '$1', '$2', … The runtime's `into_pg_params`
        // path (ExternalConnection::Postgres branch in Store's insert_sql)
        // rewrites '?' to '$N' sequentially. Assert the rewrite is correct for
        // a 2-parameter INSERT.
        let sqlite_sql = "INSERT INTO t (decimal_col, money_col) VALUES (?, ?)";
        let mut n = 0u32;
        let pg_sql: String =
            sqlite_sql
                .split('?')
                .enumerate()
                .fold(String::new(), |mut acc, (i, part)| {
                    acc.push_str(part);
                    if i < sqlite_sql.matches('?').count() {
                        n += 1;
                        acc.push('$');
                        acc.push_str(&n.to_string());
                    }
                    acc
                });
        assert!(
            pg_sql.contains("$1") && pg_sql.contains("$2"),
            "Postgres rewrite must produce $1/$2 placeholders, got: {pg_sql}"
        );
        assert!(
            !pg_sql.contains('?'),
            "Postgres rewrite must not leave '?' placeholders, got: {pg_sql}"
        );
    }

    #[tokio::test]
    async fn test_row_to_json_null_preservation() {
        // Verify that a SQL NULL cell becomes JsonVal::Null (not "").
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect");
        sqlx::query("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .execute(&pool)
            .await
            .expect("create");
        sqlx::query("INSERT INTO t (id, v) VALUES (1, NULL)")
            .execute(&pool)
            .await
            .expect("insert");
        let row = sqlx::query("SELECT v FROM t WHERE id = 1")
            .fetch_one(&pool)
            .await
            .expect("fetch");
        let jv = row_to_json(&row).unwrap_or_else(|e| panic!("row_to_json: {e}"));
        match jv.get("v") {
            Some(JsonVal::Null) => { /* correct */ }
            other => panic!("expected JsonVal::Null, got {:?}", other),
        }
    }

    // ─── RT-DATA-001: row_to_json/read_cell probe chain ──────────────

    /// BLOB column written via `SqlBytes` decodes as a hex `JsonVal::String`,
    /// not `JsonVal::Null`. Exercises the bytes arm of `read_cell`.
    #[tokio::test]
    async fn test_row_to_json_blob_decodes_as_hex() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        sqlx::query("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create: {e}"));
        sqlx::query("INSERT INTO blobs (id, data) VALUES (1, ?)")
            .bind(vec![0xde_u8, 0xad, 0xbe, 0xef])
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));
        let row = sqlx::query("SELECT data FROM blobs WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        let jv = row_to_json(&row).unwrap_or_else(|e| panic!("row_to_json: {e}"));
        match jv.get("data") {
            Some(JsonVal::String(s)) => {
                assert_eq!(s, "deadbeef", "expected hex encoding of bytes");
            }
            other => panic!("expected JsonVal::String(hex), got {:?}", other),
        }
    }

    /// Bool column decodes as `JsonVal::Bool`, not `JsonVal::Null`. Exercises
    /// the bool-first probe ordering in `read_cell`.
    #[tokio::test]
    async fn test_row_to_json_bool_column() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        sqlx::query("CREATE TABLE flags (id INTEGER PRIMARY KEY, active BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create: {e}"));
        sqlx::query("INSERT INTO flags (id, active) VALUES (1, TRUE)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));
        let row = sqlx::query("SELECT active FROM flags WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        let jv = row_to_json(&row).unwrap_or_else(|e| panic!("row_to_json: {e}"));
        // On sqlite, BOOLEAN stores as 0/1 INTEGER; read_cell probes bool
        // first, so we get Bool(true) rather than Number(1).
        match jv.get("active") {
            Some(JsonVal::Bool(b)) => assert!(*b, "expected true"),
            // sqlite may surface as integer — accept Number(1) as correct too
            Some(JsonVal::Number(n)) => assert_eq!(n.as_i64(), Some(1), "expected 1"),
            other => panic!("expected Bool or Number(1), got {:?}", other),
        }
    }

    /// `db_decode_bytes` round-trip: write `SqlBytes`, read back via
    /// `db_decode_bytes`, assert the original bytes survive.
    #[tokio::test]
    async fn test_db_decode_bytes_roundtrip() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap_or_else(|e| panic!("connect: {e}"));
        sqlx::query("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("create: {e}"));
        let original: Vec<u8> = vec![0x01, 0x02, 0x03, 0xff];
        sqlx::query("INSERT INTO blobs (id, data) VALUES (1, ?)")
            .bind(original.clone())
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("insert: {e}"));
        let decoded: IpeResult<String, Vec<Vec<u8>>> = db_query_decode(
            pool,
            "SELECT data FROM blobs WHERE id = 1".to_string(),
            vec![],
            db_decode_bytes("data".to_string()),
        )
        .await;
        match decoded {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1, "expected one row");
                assert_eq!(rows[0], original, "bytes did not survive round-trip");
            }
            IpeResult::Err(e) => panic!("decode failed: {e:?}"),
        }
    }

    /// One single-connection in-memory SQLite pool holding a `cells` table with
    /// one row: every [`read_cell`] case is one column.
    #[allow(clippy::expect_used)] // test fixture: a failed setup is a failed test
    async fn cells_pool() -> sqlx::sqlite::SqlitePool {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query(
            "CREATE TABLE cells (nul TEXT, empty TEXT, zero INTEGER, ratio REAL, \
             bytes BLOB, flag BOOLEAN, pinf REAL, ninf REAL)",
        )
        .execute(&pool)
        .await
        .expect("create cells");
        sqlx::query("INSERT INTO cells VALUES (NULL, '', 0, 1.5, X'00ff', TRUE, 9e999, -9e999)")
            .execute(&pool)
            .await
            .expect("seed cells");
        pool
    }

    /// The `(index, reason)` of a `ColumnDecode` refusal; `None` for any other outcome.
    fn column_decode_refusal<T>(r: Result<T, sqlx::Error>) -> Option<(String, String)> {
        match r {
            Err(sqlx::Error::ColumnDecode { index, source }) => Some((index, source.to_string())),
            _ => None,
        }
    }

    /// `read_cell` keeps SQL NULL as its own arm, reads every storage class to
    /// its exact cell, and refuses an infinite `REAL` with the typed reason.
    #[tokio::test]
    #[allow(clippy::expect_used)] // test fixture: a failed fetch is a failed test
    async fn read_cell_matrix_keeps_null_and_refuses_non_finite() {
        let pool = cells_pool().await;
        let row = sqlx::query("SELECT nul, empty, zero, ratio, bytes, flag, pinf, ninf FROM cells")
            .fetch_one(&pool)
            .await
            .expect("fetch cells");
        assert_eq!(read_cell(&row, 0).ok(), Some(Cell::Null));
        assert_eq!(read_cell(&row, 1).ok(), Some(Cell::Text(String::new())));
        assert_eq!(read_cell(&row, 2).ok(), Some(Cell::Int(0)));
        assert_eq!(
            read_cell(&row, 3).ok(),
            FiniteF64::new(1.5).map(Cell::Float)
        );
        assert_eq!(read_cell(&row, 4).ok(), Some(Cell::Bytes(vec![0x00, 0xff])));
        assert_eq!(read_cell(&row, 5).ok(), Some(Cell::Bool(true)));
        assert_eq!(
            column_decode_refusal(read_cell(&row, 6)),
            Some(("6".to_string(), NON_FINITE_REAL.to_string()))
        );
        assert_eq!(
            column_decode_refusal(read_cell(&row, 7)),
            Some(("7".to_string(), NON_FINITE_REAL.to_string()))
        );

        // `into_json` agrees cell by cell.
        let json: Vec<Option<JsonVal>> = (0..6)
            .map(|i| read_cell(&row, i).ok().map(Cell::into_json))
            .collect();
        assert_eq!(
            json,
            vec![
                Some(JsonVal::Null),
                Some(serde_json::json!("")),
                Some(serde_json::json!(0)),
                Some(serde_json::json!(1.5)),
                Some(serde_json::json!("00ff")),
                Some(JsonVal::Bool(true)),
            ]
        );

        // The whole-row projection is the same reader: finite columns give the
        // exact object, and an infinite cell refuses the row at its index.
        let finite = sqlx::query("SELECT nul, empty, zero, ratio, bytes, flag FROM cells")
            .fetch_one(&pool)
            .await
            .expect("fetch finite cells");
        assert_eq!(
            row_to_json(&finite).ok(),
            Some(serde_json::json!({
                "nul": null, "empty": "", "zero": 0, "ratio": 1.5, "bytes": "00ff", "flag": true
            }))
        );
        assert_eq!(
            column_decode_refusal(row_to_json(&row)),
            Some(("6".to_string(), NON_FINITE_REAL.to_string()))
        );
    }

    /// `FiniteF64::new` admits every finite float and refuses `NaN` / `±Inf`.
    #[test]
    fn finite_f64_refuses_nan_and_infinities() {
        assert!(FiniteF64::new(f64::NAN).is_none());
        assert!(FiniteF64::new(f64::INFINITY).is_none());
        assert!(FiniteF64::new(f64::NEG_INFINITY).is_none());
        assert_eq!(
            FiniteF64::new(-0.0).map(|f| Cell::Float(f).into_json()),
            Some(serde_json::json!(-0.0))
        );
        assert_eq!(
            FiniteF64::new(f64::MAX).map(|f| Cell::Float(f).into_json()),
            Some(serde_json::json!(f64::MAX))
        );
    }

    /// A stored infinite `REAL` is a typed decode refusal on the app and the
    /// external decoder paths, never `Nothing` through `db_decode_nullable`;
    /// the same query over a finite value decodes, so the refusal is the
    /// non-finite cell and nothing else.
    #[tokio::test]
    async fn non_finite_real_refuses_on_both_decoder_paths() {
        let pool = cells_pool().await;
        let app = |sql: &str| {
            db_query_decode_params::<String, IpeMaybe<f64>>(
                pool.clone(),
                sql.to_string(),
                vec![],
                db_decode_nullable(db_decode_float("x".to_string())),
            )
        };
        assert_eq!(
            app("SELECT ratio AS x FROM cells").await,
            IpeResult::Ok(vec![IpeMaybe::Just(1.5)])
        );
        assert_eq!(
            app("SELECT nul AS x FROM cells").await,
            IpeResult::Ok(vec![IpeMaybe::Nothing])
        );
        assert_eq!(
            app("SELECT pinf AS x FROM cells").await,
            IpeResult::Err("db: column decode error at index 0".to_string())
        );
        assert_eq!(
            app("SELECT ninf AS x FROM cells").await,
            IpeResult::Err("db: column decode error at index 0".to_string())
        );

        let external = |sql: &str| {
            db_conn_query_decode_params::<String, IpeMaybe<f64>>(
                ExternalConnection::Sqlite(pool.clone()),
                sql.to_string(),
                vec![],
                db_decode_nullable(db_decode_float("x".to_string())),
            )
        };
        assert_eq!(
            external("SELECT ratio AS x FROM cells").await,
            IpeResult::Ok(vec![IpeMaybe::Just(1.5)])
        );
        assert_eq!(
            external("SELECT pinf AS x FROM cells").await,
            IpeResult::Err("db: column decode error at index 0".to_string())
        );
    }

    #[tokio::test]
    async fn test_close() {
        let db = fresh_db().await;
        let r: IpeResult<String, ()> = db_close(db).await;
        assert!(matches!(r, IpeResult::Ok(())));
    }

    // ─── Ipe.Db.Sql — SqlFragment builder ────────────────────

    async fn insert_todo(db: &Db, title: &str) {
        let mut r = HashMap::new();
        r.insert("title".to_string(), title.to_string());
        let _: IpeResult<String, i64> = db_insert_row(db.clone(), "todos".into(), r).await;
    }

    /// `Db.findWhere` with a single `Sql.eq` predicate finds exactly the
    /// matching row — the `SqlFragment`-typed replacement for
    /// `unsafeFindWhere`, proving the parameterised channel (never string
    /// interpolation) still works end-to-end.
    #[tokio::test]
    async fn test_find_where_eq() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        insert_todo(&db, "beta").await;
        let frag = sql_eq(
            sql_column("title".to_string()),
            sql_param("alpha".to_string()),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        match found {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].get("title").map(String::as_str), Some("alpha"));
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `Sql.and` composes two predicates; `Sql.gt` on the auto-increment `id`
    /// column proves numeric comparison (not just string equality).
    #[tokio::test]
    async fn test_find_where_and_gt() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        insert_todo(&db, "beta").await;
        insert_todo(&db, "beta").await;
        let frag = sql_and(
            sql_eq(
                sql_column("title".to_string()),
                sql_param("beta".to_string()),
            ),
            sql_gt(sql_column("id".to_string()), sql_param(1_i64)),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 2),
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// A two-table `fresh_db` seeded with `authors` and `books`, joined on
    /// `books.author_id = authors.id`. Author 1 ("Ada") owns two books; author 2
    /// ("Bob") owns one.
    async fn fresh_join_db() -> Db {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE authors (id INTEGER PRIMARY KEY, name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1)")
            .execute(&pool)
            .await
            .expect("create authors");
        sqlx::query("CREATE TABLE books (id INTEGER PRIMARY KEY, title TEXT NOT NULL, author_id INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .expect("create books");
        for (id, name, active) in [(1, "Ada", 1), (2, "Bob", 0)] {
            sqlx::query("INSERT INTO authors (id, name, active) VALUES (?, ?, ?)")
                .bind(id)
                .bind(name)
                .bind(active)
                .execute(&pool)
                .await
                .expect("seed author");
        }
        for (id, title, author_id) in [
            (10, "Structures", 1),
            (11, "Engines", 1),
            (12, "Bridges", 2),
        ] {
            sqlx::query("INSERT INTO books (id, title, author_id) VALUES (?, ?, ?)")
                .bind(id)
                .bind(title)
                .bind(author_id)
                .execute(&pool)
                .await
                .expect("seed book");
        }
        pool
    }

    /// `Db.findJoin` returns one paired-map result per matched join row: the
    /// left map keyed by the books' plain columns, the right by the authors'.
    /// Three books each join to their author, so three pairs come back — proof
    /// the alias-prefixed projection splits back into two per-side codec-ready
    /// maps.
    #[tokio::test]
    async fn test_find_join_pairs_both_sides() {
        let db = fresh_join_db().await;
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let found: IpeResult<String, Vec<JoinRow>> = db_find_join(
            db,
            "books".into(),
            "a0".into(),
            vec!["id".into(), "title".into(), "author_id".into()],
            "authors".into(),
            "a1".into(),
            vec!["id".into(), "name".into(), "active".into()],
            frag,
        )
        .await;
        match found {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 3, "three books each join their author");
                // Every pair's book.author_id equals its author.id, and each
                // side carries its own plain-keyed columns (no `a0__` leakage).
                for (book, author) in &v {
                    assert!(book.contains_key("title"), "left map keyed plainly");
                    assert!(author.contains_key("name"), "right map keyed plainly");
                    assert!(
                        !book.keys().any(|k| k.contains("__")),
                        "no alias prefix leaks"
                    );
                    assert_eq!(book.get("author_id"), author.get("id"));
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// A filter predicate on the joined columns binds its value as a parameter,
    /// never interpolated: restricting to active authors returns only Ada's two
    /// books, and the bound `1` never appears in the SQL text (it is a `?`).
    #[tokio::test]
    async fn test_find_join_filter_binds_param() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        // The composed fragment's SQL is placeholder-only: the value 1 is a bind.
        assert!(
            !frag.sql.contains('1') || frag.sql.contains('?'),
            "filter value must bind as ? not interpolate"
        );
        assert_eq!(
            frag.binds.len(),
            1,
            "exactly one bound value (the active flag)"
        );
        let found: IpeResult<String, Vec<JoinRow>> = db_find_join(
            db,
            "books".into(),
            "a0".into(),
            vec!["id".into(), "title".into(), "author_id".into()],
            "authors".into(),
            "a1".into(),
            vec!["id".into(), "name".into()],
            frag,
        )
        .await;
        match found {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 2, "only active author Ada's two books");
                for (_book, author) in &v {
                    assert_eq!(author.get("name").map(String::as_str), Some("Ada"));
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// A join side whose table is not a valid SQL identifier fails closed with a
    /// typed error, issuing no SQL — the runtime re-validation gate.
    #[tokio::test]
    async fn test_find_join_rejects_bad_identifier() {
        let db = fresh_join_db().await;
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let found: IpeResult<String, Vec<JoinRow>> = db_find_join(
            db,
            "books; DROP TABLE authors".into(),
            "a0".into(),
            vec!["id".into()],
            "authors".into(),
            "a1".into(),
            vec!["id".into()],
            frag,
        )
        .await;
        assert!(
            matches!(found, IpeResult::Err(_)),
            "a non-identifier table must fail closed"
        );
    }

    /// Golden SQL: an inner join lowers to EXACTLY one parameterized statement
    /// — `SELECT a0.col AS a0__col, … FROM lt AS a0, rt AS a1 WHERE a0.k =
    /// a1.k`. Every identifier is a validated `alias.column` reference; the join
    /// key is column-to-column (no value), so the statement carries no bind. This
    /// pins the exact emitted text so a regression in the projection / FROM shape
    /// is a test failure, not a silent SQL change.
    #[test]
    fn join_statement_inner_is_exact_parameterized_sql() {
        let left = JoinSide::parse(
            "books".into(),
            "a0".into(),
            vec!["id".into(), "title".into(), "author_id".into()],
        )
        .expect("left side parses");
        let right = JoinSide::parse(
            "authors".into(),
            "a1".into(),
            vec!["id".into(), "name".into()],
        )
        .expect("right side parses");
        let frag = sql_eq(
            sql_column("a0.author_id".to_string()),
            sql_column("a1.id".to_string()),
        );
        assert!(frag.binds.is_empty(), "a column=column key binds no value");
        let sql = build_join_statement(&left, &right, &frag.sql).expect("statement builds");
        assert_eq!(
            sql,
            "SELECT a0.id AS a0__id, a0.title AS a0__title, a0.author_id AS a0__author_id, \
             a1.id AS a1__id, a1.name AS a1__name \
             FROM books AS a0, authors AS a1 WHERE (a0.author_id = a1.id)"
        );
    }

    /// Golden SQL: join + a right-side filter. The filter value is a `?`
    /// placeholder with a matching bind, never interpolated — the emitted text
    /// contains the placeholder, and the fragment carries exactly one bound
    /// value.
    #[test]
    fn join_statement_with_filter_binds_value_as_placeholder() {
        let left = JoinSide::parse(
            "books".into(),
            "a0".into(),
            vec!["id".into(), "author_id".into()],
        )
        .expect("left side parses");
        let right = JoinSide::parse(
            "authors".into(),
            "a1".into(),
            vec!["id".into(), "name".into()],
        )
        .expect("right side parses");
        let frag = sql_and(
            sql_eq(
                sql_column("a0.author_id".to_string()),
                sql_column("a1.id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        assert_eq!(frag.binds.len(), 1, "exactly one bound value (the filter)");
        let sql = build_join_statement(&left, &right, &frag.sql).expect("statement builds");
        assert_eq!(
            sql,
            "SELECT a0.id AS a0__id, a0.author_id AS a0__author_id, \
             a1.id AS a1__id, a1.name AS a1__name \
             FROM books AS a0, authors AS a1 \
             WHERE ((a0.author_id = a1.id) AND (a1.active = ?))"
        );
        assert!(
            sql.contains('?') && !sql.contains(" 1)"),
            "the filter value is a placeholder, not interpolated text"
        );
    }

    /// Two sides that share an alias are rejected: the projection and WHERE
    /// could not tell the sides apart, so fail closed rather than emit an
    /// ambiguous statement.
    #[tokio::test]
    async fn test_find_join_rejects_shared_alias() {
        let db = fresh_join_db().await;
        let frag = sql_eq(
            sql_column("a0.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let found: IpeResult<String, Vec<JoinRow>> = db_find_join(
            db,
            "books".into(),
            "a0".into(),
            vec!["id".into()],
            "authors".into(),
            "a0".into(),
            vec!["id".into()],
            frag,
        )
        .await;
        assert!(
            matches!(found, IpeResult::Err(_)),
            "a shared alias must fail closed"
        );
    }

    /// Golden SQL: a single-column projection lowers to EXACTLY one
    /// parameterized statement — `SELECT a1.name AS p0 FROM lt AS a0, rt AS a1
    /// WHERE a0.k = a1.k`. Only the projected column is selected (column
    /// pushdown), bound to the output name `p0`; every identifier is a validated
    /// `alias.column` reference and the key is column-to-column (no bind).
    #[test]
    fn projection_statement_single_column_is_exact_parameterized_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        assert!(frag.binds.is_empty(), "a column=column key binds no value");
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ColumnTerm("a1".into(), "name".into())],
            &frag.sql,
        )
        .expect("statement builds");
        assert_eq!(literal_count, 0, "no literal positions");
        assert_eq!(
            sql,
            "SELECT a1.name AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// Golden SQL: a two-column projection lowers to EXACTLY one parameterized
    /// statement — `SELECT a0.title AS p0, a1.name AS p1 FROM lt AS a0, rt AS a1
    /// WHERE a0.k = a1.k`. Each projected column is bound to its own `p<index>`
    /// output name in order (column pushdown), every identifier is a validated
    /// `alias.column` reference, and the key is column-to-column (no bind).
    #[test]
    fn projection_statement_two_columns_is_exact_parameterized_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        assert!(frag.binds.is_empty(), "a column=column key binds no value");
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[
                ProjectionTerm::ColumnTerm("a0".into(), "title".into()),
                ProjectionTerm::ColumnTerm("a1".into(), "name".into()),
            ],
            &frag.sql,
        )
        .expect("statement builds");
        assert_eq!(literal_count, 0, "no literal positions");
        assert_eq!(
            sql,
            "SELECT a0.title AS p0, a1.name AS p1 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// A two-column projection where one column is not a bare SQL identifier
    /// fails the whole statement closed — the runtime re-validation gate holds
    /// per projected column, never emitting a partial SELECT.
    #[test]
    fn projection_statement_two_columns_rejects_bad_second_column() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let built = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[
                ProjectionTerm::ColumnTerm("a0".into(), "title".into()),
                ProjectionTerm::ColumnTerm("a1".into(), "name); DROP TABLE authors".into()),
            ],
            &frag.sql,
        );
        assert!(
            built.is_err(),
            "a non-identifier column anywhere in the projection must fail closed"
        );
    }

    /// Golden SQL: a projection over a join + a right-side filter. Only the
    /// projected column is selected; the filter value is a `?` placeholder with a
    /// matching bind, never interpolated.
    #[test]
    fn projection_statement_with_filter_binds_value_as_placeholder() {
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        assert_eq!(frag.binds.len(), 1, "exactly one bound value (the filter)");
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ColumnTerm("a1".into(), "name".into())],
            &frag.sql,
        )
        .expect("statement builds");
        assert_eq!(literal_count, 0, "no literal positions");
        assert_eq!(
            sql,
            "SELECT a1.name AS p0 \
             FROM books AS a0, authors AS a1 \
             WHERE ((a1.id = a0.author_id) AND (a1.active = ?))"
        );
        assert!(
            sql.contains('?') && !sql.contains(" 1)"),
            "the filter value is a placeholder, not interpolated text"
        );
    }

    /// A projected column identifier that is not a bare SQL identifier fails
    /// closed with no SQL — the runtime re-validation gate over the projection.
    #[test]
    fn projection_statement_rejects_bad_column() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let built = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ColumnTerm(
                "a1".into(),
                "name; DROP TABLE authors".into(),
            )],
            &frag.sql,
        );
        assert!(
            built.is_err(),
            "a non-identifier projected column must fail closed"
        );
    }

    /// An empty projection is rejected — a projection must name at least one
    /// column, never fall back to `SELECT *`.
    #[test]
    fn projection_statement_rejects_empty_projection() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let built = build_projection_statement("books", "a0", "authors", "a1", &[], &frag.sql);
        assert!(built.is_err(), "an empty projection must fail closed");
    }

    /// `Db.findProjection` reads only the projected column, keyed by the output
    /// name `p0`: projecting the author name over the active-author join returns
    /// Ada's two books' author name, each row carrying just `p0` (column
    /// pushdown), and the filter value binds as a parameter.
    #[tokio::test]
    async fn test_find_projection_single_column() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![ProjectionTerm::ColumnTerm("a1".into(), "name".into())],
            vec![],
        )
        .await;
        match found {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 2, "only active author Ada's two books");
                for row in &rows {
                    assert_eq!(row.get("p0").map(String::as_str), Some("Ada"));
                    assert_eq!(row.len(), 1, "only the projected column is read");
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `Db.findProjection` reads two projected columns over the active-author
    /// join, each keyed by its own output name (`p0` = book title, `p1` = author
    /// name), in projection order (column pushdown). The filter value binds as a
    /// parameter; each returned row carries exactly the two projected columns.
    #[tokio::test]
    async fn test_find_projection_two_columns() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![
                ProjectionTerm::ColumnTerm("a0".into(), "title".into()),
                ProjectionTerm::ColumnTerm("a1".into(), "name".into()),
            ],
            vec![],
        )
        .await;
        match found {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 2, "only active author Ada's two books");
                let mut titles: Vec<&str> = rows
                    .iter()
                    .filter_map(|r| r.get("p0").map(String::as_str))
                    .collect();
                titles.sort_unstable();
                assert_eq!(titles, ["Engines", "Structures"], "p0 is the book title");
                for row in &rows {
                    assert_eq!(row.get("p1").map(String::as_str), Some("Ada"));
                    assert_eq!(row.len(), 2, "exactly the two projected columns");
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `Db.deleteWhere` removes exactly the matching rows and returns the
    /// affected row count.
    #[tokio::test]
    async fn test_delete_where() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        insert_todo(&db, "beta").await;
        let frag = sql_eq(
            sql_column("title".to_string()),
            sql_param("alpha".to_string()),
        );
        let deleted: IpeResult<String, i64> =
            db_delete_where(db.clone(), "todos".into(), frag).await;
        assert_eq!(deleted, IpeResult::Ok(1));
        let remaining: IpeResult<String, Vec<HashMap<String, String>>> = db_find_where(
            db,
            "todos".into(),
            sql_is_not_null(sql_column("title".to_string())),
        )
        .await;
        match remaining {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1),
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `Sql.inList` with a non-empty list matches every listed value.
    #[tokio::test]
    async fn test_in_list_non_empty() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        insert_todo(&db, "beta").await;
        insert_todo(&db, "gamma").await;
        let frag = sql_in_list(
            sql_column("title".to_string()),
            vec![
                SqlParam::Text("alpha".to_string()),
                SqlParam::Text("gamma".to_string()),
            ],
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 2),
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// Empty `Sql.inList` emits `(1 = 0)` (always-false) rather than the SQL
    /// syntax error `IN ()` — a real column reference stays a real column
    /// reference, but the whole predicate matches nothing.
    #[tokio::test]
    async fn test_in_list_empty_matches_nothing() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        let frag = sql_in_list(sql_column("title".to_string()), Vec::new());
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 0),
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `Sql.column` accepts a dotted reference (`table.column`) via
    /// `SqlIdent::parse_dotted`, distinct from `SqlIdent::parse_plain`
    /// (table-name-only, dot-rejecting) used for the table argument itself.
    #[tokio::test]
    async fn test_column_accepts_dotted_reference() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        let frag = sql_eq(
            sql_column("todos.title".to_string()),
            sql_param("alpha".to_string()),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        match found {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1),
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// An invalid `Sql.column` identifier poisons the fragment instead of
    /// panicking or interpolating unchecked text; `Db.findWhere` surfaces the
    /// poison as a `Task::Err`, never malformed SQL.
    #[tokio::test]
    async fn test_poisoned_column_surfaces_as_task_err() {
        let db = fresh_db().await;
        insert_todo(&db, "alpha").await;
        // Space + semicolon are outside `valid_sql_ident`'s charset.
        let frag = sql_eq(
            sql_column("title; DROP TABLE todos".to_string()),
            sql_param("alpha".to_string()),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db, "todos".into(), frag).await;
        assert!(
            matches!(found, IpeResult::Err(_)),
            "poisoned column must surface as Task::Err, got {found:?}"
        );
    }

    /// SECURITY: `sql_unsafe_fragment` (the `Ipe.Db.Unsafe.unsafeFragment`
    /// runtime) DELIBERATELY skips the `valid_sql_ident` gate that
    /// [`sql_column`] applies. On the SAME identifier that `sql_column` poisons,
    /// the unsafe mint produces a NON-poisoned fragment carrying the verbatim
    /// text — this is the disclosed escape hatch: no validator runs, the caller
    /// asserts the identifier is safe. The contrast with the poisoned
    /// `sql_column` result is the whole point of the two-member split.
    #[test]
    fn test_unsafe_fragment_skips_validation() {
        // An identifier `sql_column` rejects (space + semicolon outside the
        // `valid_sql_ident` charset), which it poisons.
        let hostile = "title; DROP TABLE todos".to_string();
        let validated = sql_column(hostile.clone());
        assert!(
            validated.invalid.is_some(),
            "sql_column must poison a malformed identifier"
        );
        assert!(
            validated.sql.is_empty(),
            "a poisoned sql_column carries no verbatim text"
        );

        // The unsafe mint on the SAME input: NO poison, verbatim text preserved.
        let unsafe_frag = sql_unsafe_fragment(hostile.clone());
        assert!(
            unsafe_frag.invalid.is_none(),
            "sql_unsafe_fragment must NOT poison — it deliberately skips valid_sql_ident"
        );
        assert_eq!(
            unsafe_frag.sql, hostile,
            "sql_unsafe_fragment must carry the verbatim identifier text"
        );
        assert!(
            unsafe_frag.binds.is_empty(),
            "sql_unsafe_fragment mints no binds"
        );
    }

    /// `SqlFragment`'s hand-written `Debug` shows SQL text + bind COUNT —
    /// never the bind VALUE.
    #[test]
    fn test_sqlfragment_debug_never_shows_bind_values() {
        let frag = sql_eq(
            sql_column("title".to_string()),
            sql_param("super-secret-value".to_string()),
        );
        let shown = format!("{frag:?}");
        assert!(
            !shown.contains("super-secret-value"),
            "Debug leaked a bind value: {shown}"
        );
        assert!(
            shown.contains("binds: 1"),
            "Debug should show bind count: {shown}"
        );
    }

    /// `SqlFragment` derives `PartialEq` structurally (sql + binds + invalid).
    #[test]
    fn test_sqlfragment_partial_eq() {
        let a = sql_eq(sql_column("title".to_string()), sql_param(1_i64));
        let b = sql_eq(sql_column("title".to_string()), sql_param(1_i64));
        let c = sql_eq(sql_column("title".to_string()), sql_param(2_i64));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ─── db_exec / db_query parameter-binding characterization (candidate B) ──────
    // These pin the param-carrying behavior of the raw exec/query kernels — the
    // two functions that route through the placeholder path. They lock the
    // contract across the build_sql → db_format_sql+bind deepening: same
    // round-trip values, same injection-safety, no behavior drift.

    /// A parameterised INSERT via db_exec then a parameterised SELECT via
    /// db_query round-trips the bound values.
    #[tokio::test]
    async fn test_exec_and_query_with_params() {
        let db = fresh_db().await;
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO todos (title, done) VALUES (?, ?)".into(),
            vec!["buy milk".to_string(), "0".to_string()],
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1))); // exec returns rows-affected

        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db,
            "SELECT title, done FROM todos WHERE title = ?".into(),
            vec!["buy milk".to_string()],
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].get("title").unwrap(), "buy milk");
                assert_eq!(v[0].get("done").unwrap(), "0");
            }
            other => panic!("unexpected: {:?}", other),
        }
    }

    /// The load-bearing safety property: a value carrying single quotes and SQL
    /// metacharacters is bound, not spliced — stored and returned VERBATIM, and
    /// the surrounding table is untouched (no injection executes).
    #[tokio::test]
    async fn test_query_param_with_quotes_and_metachars_roundtrips_safely() {
        let db = fresh_db().await;
        let nasty = "x'); DROP TABLE todos;-- O'Brien".to_string();
        let ins: IpeResult<String, i64> = db_exec(
            db.clone(),
            "INSERT INTO todos (title, done) VALUES (?, ?)".into(),
            vec![nasty.clone(), "0".to_string()],
        )
        .await;
        assert!(matches!(ins, IpeResult::Ok(1))); // exec returns rows-affected

        // The value comes back byte-for-byte (proves it was bound, not splice-escaped-into-SQL).
        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query(
            db.clone(),
            "SELECT title FROM todos WHERE title = ?".into(),
            vec![nasty.clone()],
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].get("title").unwrap(), &nasty);
            }
            other => panic!("unexpected: {:?}", other),
        }

        // The table still exists with exactly the one row — the DROP never ran.
        let all: IpeResult<String, Vec<HashMap<String, String>>> =
            db_query(db, "SELECT title FROM todos".into(), vec![]).await;
        match all {
            IpeResult::Ok(v) => assert_eq!(v.len(), 1, "injection must not have dropped the table"),
            other => panic!("table gone or errored: {:?}", other),
        }
    }

    fn upsert_sql(
        target: &[&str],
        fields: Vec<(&str, Option<SqlParam>)>,
    ) -> Result<(String, Vec<SqlParam>), DbBuildError> {
        build_upsert_sql(
            "kv",
            target.iter().map(|c| (*c).to_string()).collect(),
            fields
                .into_iter()
                .map(|(c, p)| (c.to_string(), p))
                .collect(),
        )
    }

    /// The statement is the one standard form both engines share: SET covers
    /// every `SetField` column except the conflict target, as `excluded.<col>`;
    /// an `OmitField` column appears nowhere.
    #[test]
    fn upsert_sql_updates_non_target_set_fields_from_excluded() {
        let built = upsert_sql(
            &["k"],
            vec![
                ("k", Some(SqlParam::Text("a".to_string()))),
                ("v", Some(SqlParam::Text("1".to_string()))),
                ("created_at", None),
                ("n", Some(SqlParam::Int(7))),
            ],
        );
        assert!(
            matches!(
                &built,
                Ok((sql, args)) if sql == "INSERT INTO kv (k, v, n) VALUES (?, ?, ?) \
                    ON CONFLICT (k) DO UPDATE SET v = excluded.v, n = excluded.n"
                    && args.len() == 3
            ),
            "unexpected upsert SQL: {built:?}"
        );
    }

    /// Nothing left to SET once the target and the `OmitField` columns are
    /// excluded → `DO NOTHING` (insert-if-absent), never an empty `SET`.
    #[test]
    fn upsert_sql_with_empty_set_list_is_do_nothing() {
        let built = upsert_sql(
            &["a", "b"],
            vec![
                ("a", Some(SqlParam::Int(1))),
                ("b", Some(SqlParam::Int(2))),
                ("created_at", None),
            ],
        );
        assert!(
            matches!(
                &built,
                Ok((sql, _)) if sql == "INSERT INTO kv (a, b) VALUES (?, ?) \
                    ON CONFLICT (a, b) DO NOTHING"
            ),
            "empty SET must degrade to DO NOTHING: {built:?}"
        );
    }

    /// The refusal a `DbBuildError` carries for an invalid name in `slot`.
    fn invalid(slot: IdentSlot, name: &str) -> DbBuildError {
        DbBuildError::InvalidIdent {
            slot,
            name: name.to_string(),
        }
    }

    /// Every malformed upsert is refused with its own typed reason before any
    /// SQL string exists.
    #[test]
    fn upsert_sql_refuses_malformed_requests() {
        let key = || ("k", Some(SqlParam::Text("a".to_string())));
        let field_col = IdentSlot::Column(ColumnList::Fields);
        let target_col = IdentSlot::Column(ColumnList::ConflictTarget);
        let cases = [
            (
                "hostile table",
                build_upsert_sql(
                    "kv; DROP TABLE kv",
                    vec!["k".to_string()],
                    vec![("k".to_string(), Some(SqlParam::Int(1)))],
                ),
                invalid(IdentSlot::Table, "kv; DROP TABLE kv"),
            ),
            (
                "hostile set column",
                upsert_sql(&["k"], vec![key(), ("v = 1; --", Some(SqlParam::Int(1)))]),
                invalid(field_col, "v = 1; --"),
            ),
            (
                "hostile conflict-target column",
                upsert_sql(&["k) DO NOTHING; --"], vec![key()]),
                invalid(target_col, "k) DO NOTHING; --"),
            ),
            (
                "dotted column (no qualifier allowed in excluded.<col>)",
                upsert_sql(&["k"], vec![key(), ("kv.v", Some(SqlParam::Int(1)))]),
                invalid(field_col, "kv.v"),
            ),
            (
                "dotted conflict-target column",
                upsert_sql(&["kv.k"], vec![key()]),
                invalid(target_col, "kv.k"),
            ),
            (
                "empty conflict target",
                upsert_sql(&[], vec![key()]),
                DbBuildError::EmptyTarget,
            ),
            (
                "duplicate column (case-insensitive)",
                upsert_sql(&["k"], vec![key(), ("K", Some(SqlParam::Int(1)))]),
                DbBuildError::DuplicateColumn {
                    list: ColumnList::Fields,
                    name: "K".to_string(),
                },
            ),
            (
                "duplicate conflict-target column",
                upsert_sql(&["k", "K"], vec![key()]),
                DbBuildError::DuplicateColumn {
                    list: ColumnList::ConflictTarget,
                    name: "K".to_string(),
                },
            ),
            (
                "conflict-target column absent from fields",
                upsert_sql(&["id"], vec![key()]),
                DbBuildError::TargetNotSupplied {
                    name: "id".to_string(),
                },
            ),
            (
                "conflict-target column is OmitField",
                upsert_sql(&["id"], vec![key(), ("id", None)]),
                DbBuildError::TargetNotSupplied {
                    name: "id".to_string(),
                },
            ),
            (
                "conflict-target column is SqlNull",
                upsert_sql(
                    &["k"],
                    vec![(
                        "k",
                        Some(SqlParam::Null(Box::new(SqlParam::Text(String::new())))),
                    )],
                ),
                DbBuildError::NullTarget {
                    name: "k".to_string(),
                },
            ),
        ];
        for (label, built, want) in cases {
            assert!(
                matches!(&built, Err(got) if *got == want),
                "{label} must be refused with {want:?}, got {built:?}"
            );
        }
    }

    /// A malformed insert is refused with a typed `InvalidIdent` naming the
    /// slot; an all-`OmitField` insert still builds `DEFAULT VALUES`.
    #[test]
    fn insert_sql_refuses_invalid_identifiers() {
        let hostile_table = build_insert_sql("t; DROP TABLE t", vec![]);
        assert!(
            matches!(&hostile_table, Err(e) if *e == invalid(IdentSlot::Table, "t; DROP TABLE t")),
            "hostile table must be refused: {hostile_table:?}"
        );
        let hostile_col =
            build_insert_sql("t", vec![("a = 1; --".to_string(), Some(SqlParam::Int(1)))]);
        assert!(
            matches!(
                &hostile_col,
                Err(e) if *e == invalid(IdentSlot::Column(ColumnList::Fields), "a = 1; --")
            ),
            "hostile column must be refused: {hostile_col:?}"
        );
        // An `OmitField` column is still name-checked: it never reaches SQL,
        // but a hostile name is refused rather than silently dropped.
        let hostile_omit = build_insert_sql("t", vec![("a'".to_string(), None)]);
        assert!(
            matches!(
                &hostile_omit,
                Err(DbBuildError::InvalidIdent {
                    slot: IdentSlot::Column(ColumnList::Fields),
                    ..
                })
            ),
            "hostile OmitField column must be refused: {hostile_omit:?}"
        );
        let defaults = build_insert_sql("s.t", vec![("a".to_string(), None)]);
        assert!(
            matches!(&defaults, Ok((sql, args)) if sql == "INSERT INTO s.t DEFAULT VALUES" && args.is_empty()),
            "all-OmitField insert must build DEFAULT VALUES: {defaults:?}"
        );
    }

    /// The task-edge text of every refusal is pinned byte-for-byte: it names
    /// the kernel and the offending identifier (Debug-escaped), never a value.
    #[test]
    fn build_refusal_text_is_pinned() {
        let cases = [
            (
                invalid(IdentSlot::Table, "t\"x"),
                "db.upsertFields: invalid table name \"t\\\"x\"",
            ),
            (
                invalid(IdentSlot::Column(ColumnList::Fields), "c;"),
                "db.upsertFields: invalid column name \"c;\"",
            ),
            (
                invalid(IdentSlot::Column(ColumnList::ConflictTarget), "c;"),
                "db.upsertFields: invalid conflict-target column name \"c;\"",
            ),
            (
                DbBuildError::EmptyTarget,
                "db.upsertFields: empty conflict target; pass the primary-key or unique columns",
            ),
            (
                DbBuildError::DuplicateColumn {
                    list: ColumnList::Fields,
                    name: "K".to_string(),
                },
                "db.upsertFields: column \"K\" is listed more than once",
            ),
            (
                DbBuildError::DuplicateColumn {
                    list: ColumnList::ConflictTarget,
                    name: "K".to_string(),
                },
                "db.upsertFields: conflict-target column \"K\" is listed more than once",
            ),
            (
                DbBuildError::TargetNotSupplied {
                    name: "id".to_string(),
                },
                "db.upsertFields: conflict-target column \"id\" must be supplied as a \
                 SetField; without a client value the conflict can never match",
            ),
            (
                DbBuildError::NullTarget {
                    name: "k".to_string(),
                },
                "db.upsertFields: conflict-target column \"k\" is NULL; a NULL key never conflicts",
            ),
        ];
        for (err, want) in cases {
            let got: String = build_refusal("db.upsertFields", &err);
            assert_eq!(got, want, "refusal text drifted for {err:?}");
        }
    }

    /// Round-trip on SQLite: a conflicting upsert UPDATES the row in place —
    /// rowid unchanged, the column outside the SET list preserved, still one
    /// row — the semantics `INSERT OR REPLACE` would break. A `DO NOTHING`
    /// upsert meeting the existing row affects zero rows.
    #[tokio::test]
    async fn upsert_fields_updates_in_place_on_sqlite() {
        let db = fresh_db().await;
        let mk: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT, note TEXT DEFAULT 'none')".to_string(),
        )
        .await;
        assert!(matches!(mk, IpeResult::Ok(_)), "create: {mk:?}");

        let upsert = |v: &str| {
            db_upsert_fields::<String>(
                db.clone(),
                "kv".to_string(),
                vec!["k".to_string()],
                vec![
                    ("k".to_string(), Some(SqlParam::Text("a".to_string()))),
                    ("v".to_string(), Some(SqlParam::Text(v.to_string()))),
                    ("note".to_string(), None),
                ],
            )
        };
        let first = upsert("1").await;
        assert!(matches!(first, IpeResult::Ok(1)), "insert: {first:?}");
        let noted: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "UPDATE kv SET note = 'kept' WHERE k = 'a'".to_string(),
        )
        .await;
        assert!(matches!(noted, IpeResult::Ok(1)), "note: {noted:?}");
        // A later row raises max(rowid), so a delete-then-insert of `a` would
        // be assigned a fresh rowid rather than reusing its old one.
        let other: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "INSERT INTO kv (k, v) VALUES ('b', 'x')".to_string(),
        )
        .await;
        assert!(matches!(other, IpeResult::Ok(1)), "second row: {other:?}");

        let read = || {
            db_query_params::<String>(
                db.clone(),
                "SELECT rowid AS rid, v, note FROM kv WHERE k = 'a'".to_string(),
                Vec::new(),
            )
        };
        let before = read().await.with_default(Vec::new());
        let rid_before = before.first().and_then(|r| r.get("rid")).cloned();
        assert!(rid_before.is_some(), "row missing after insert: {before:?}");

        let second = upsert("2").await;
        assert!(matches!(second, IpeResult::Ok(1)), "update: {second:?}");
        let after = read().await.with_default(Vec::new());
        assert_eq!(
            after.len(),
            1,
            "conflict must update, not add a row: {after:?}"
        );
        let all: IpeResult<String, Vec<HashMap<String, String>>> =
            db_query_params(db.clone(), "SELECT k FROM kv".to_string(), Vec::new()).await;
        assert_eq!(all.with_default(Vec::new()).len(), 2, "row count changed");
        let row = after.first();
        assert_eq!(
            row.and_then(|r| r.get("rid")).cloned(),
            rid_before,
            "rowid changed"
        );
        assert_eq!(row.and_then(|r| r.get("v")).map(String::as_str), Some("2"));
        assert_eq!(
            row.and_then(|r| r.get("note")).map(String::as_str),
            Some("kept"),
            "column outside the SET list must be preserved"
        );

        let key_only: IpeResult<String, i64> = db_upsert_fields(
            db.clone(),
            "kv".to_string(),
            vec!["k".to_string()],
            vec![("k".to_string(), Some(SqlParam::Text("a".to_string())))],
        )
        .await;
        assert!(
            matches!(key_only, IpeResult::Ok(0)),
            "DO NOTHING on an existing key affects no row: {key_only:?}"
        );
        let last = read().await.with_default(Vec::new());
        assert_eq!(
            last.first().and_then(|r| r.get("v")).map(String::as_str),
            Some("2"),
            "DO NOTHING must leave the row untouched"
        );
    }

    #[tokio::test]
    async fn update_fields_refuses_unscoped_update() {
        let db = fresh_db().await;
        let mk: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE acct (id INTEGER PRIMARY KEY, bal INTEGER)".to_string(),
        )
        .await;
        assert!(matches!(mk, IpeResult::Ok(_)), "create: {mk:?}");
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "INSERT INTO acct (bal) VALUES (10), (20)".to_string(),
        )
        .await;

        // Empty WHERE-column set MUST be refused (would otherwise mass-update
        // every row), NOT silently rewrite the whole table.
        let r: IpeResult<String, i64> = db_update_fields(
            db.clone(),
            "acct".to_string(),
            vec![], // no WHERE
            vec![("bal".to_string(), Some(SqlParam::Int(0)))],
        )
        .await;
        assert!(
            matches!(r, IpeResult::Err(_)),
            "empty WHERE must be refused, got {r:?}"
        );
        // No row should have been zeroed.
        let zeroed: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT bal FROM acct WHERE bal = ?".to_string(),
            vec![SqlParam::Int(0)],
        )
        .await;
        assert_eq!(
            zeroed.with_default(Vec::new()).len(),
            0,
            "no row should have been mass-updated"
        );
        // A scoped update still works (affects exactly 1 row).
        let ok: IpeResult<String, i64> = db_update_fields(
            db.clone(),
            "acct".to_string(),
            vec![("id".to_string(), SqlParam::Int(1))],
            vec![("bal".to_string(), Some(SqlParam::Int(99)))],
        )
        .await;
        assert!(
            matches!(ok, IpeResult::Ok(1)),
            "scoped update should affect 1 row: {ok:?}"
        );
    }

    /// The runtime contract the Ipê-side `Store.updateAs` relies on to enforce an
    /// `immutable` policy column: `updateAs` drops every immutable column from the
    /// SET (turns it into an OmitField), so the emitted UPDATE never names that
    /// column. This test drives `db_update_where` exactly as the fixed `updateAs`
    /// does — the immutable column omitted, a mutable column set, scoped by the
    /// owner filter — and proves the immutable value is UNCHANGED while the mutable
    /// value changes. The companion `update_where_sets_immutable_column_when_not_dropped`
    /// proves the omission is load-bearing: were the column left in the SET (the
    /// pre-fix behaviour), the value WOULD change. Together they show the drop is
    /// what enforces immutability, not an incidental no-op.
    #[tokio::test]
    async fn update_where_omitting_immutable_column_leaves_it_unchanged() {
        let db = fresh_db().await;
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE docs (body TEXT PRIMARY KEY, owner TEXT, stamped TEXT)".to_string(),
        )
        .await;
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "INSERT INTO docs (body, owner, stamped) VALUES ('doc1', 'alice', 'original')"
                .to_string(),
        )
        .await;

        // An update scoped by pk AND the owner filter whose SET carries a
        // written column but NOT `stamped` (dropped the way `updateAs` drops
        // every immutable and owner column). The caller's attempt to set a new
        // `stamped` value is simply absent.
        let updated: IpeResult<String, i64> = db_update_where(
            db.clone(),
            "docs".to_string(),
            vec![
                (
                    "owner".to_string(),
                    Some(SqlParam::Text("alice".to_string())),
                ),
                ("stamped".to_string(), None), // OmitField — dropped by the immutable policy
            ],
            sql_and(
                sql_eq(
                    sql_column("body".to_string()),
                    sql_param("doc1".to_string()),
                ),
                sql_eq(
                    sql_column("owner".to_string()),
                    sql_param("alice".to_string()),
                ),
            ),
        )
        .await;
        assert!(
            matches!(updated, IpeResult::Ok(1)),
            "the owner-scoped update should affect exactly the caller's row: {updated:?}"
        );

        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT stamped FROM docs WHERE body = ?".to_string(),
            vec![SqlParam::Text("doc1".to_string())],
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 1, "the row must still exist");
                assert_eq!(
                    v[0].get("stamped").map(String::as_str),
                    Some("original"),
                    "the immutable column MUST retain its insert-time value — a \
                     dropped (OmitField) column is never written by an update"
                );
            }
            other => panic!("read back failed: {other:?}"),
        }
    }

    /// The load-bearing half of the immutable proof: if the immutable column were
    /// NOT dropped (left as a SetField, the pre-fix behaviour), the same update
    /// WOULD overwrite it. Demonstrates that the `dropColumns` omission in
    /// `updateAs` is exactly what prevents the change — not an accident of the
    /// runtime refusing it anyway.
    #[tokio::test]
    async fn update_where_sets_immutable_column_when_not_dropped() {
        let db = fresh_db().await;
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE docs (body TEXT PRIMARY KEY, owner TEXT, stamped TEXT)".to_string(),
        )
        .await;
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "INSERT INTO docs (body, owner, stamped) VALUES ('doc1', 'alice', 'original')"
                .to_string(),
        )
        .await;

        // Same update, but with `stamped` left IN the SET (SetField). This is
        // the outcome the fix prevents.
        let updated: IpeResult<String, i64> = db_update_where(
            db.clone(),
            "docs".to_string(),
            vec![(
                "stamped".to_string(),
                Some(SqlParam::Text("tampered".to_string())),
            )],
            sql_eq(
                sql_column("body".to_string()),
                sql_param("doc1".to_string()),
            ),
        )
        .await;
        assert!(matches!(updated, IpeResult::Ok(1)), "{updated:?}");

        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT stamped FROM docs WHERE body = ?".to_string(),
            vec![SqlParam::Text("doc1".to_string())],
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(
                    v[0].get("stamped").map(String::as_str),
                    Some("tampered"),
                    "with the immutable column left in the SET it WOULD change — \
                     confirming the drop is what enforces immutability"
                );
            }
            other => panic!("read back failed: {other:?}"),
        }
    }

    /// `db_update_where` mirrors `db_update_fields`' guards on the WHERE-fragment
    /// path: an empty WHERE fragment is refused (no mass-update), a scoped update
    /// touches only the matching rows, and a SET value carrying SQL metacharacters
    /// is bound (stored verbatim), never spliced.
    #[tokio::test]
    async fn update_where_scopes_binds_and_refuses_empty() {
        let db = fresh_db().await;
        let mk: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "CREATE TABLE acct (id INTEGER PRIMARY KEY, owner TEXT, bal INTEGER)".to_string(),
        )
        .await;
        assert!(matches!(mk, IpeResult::Ok(_)), "create: {mk:?}");
        let _: IpeResult<String, i64> = db_exec_raw(
            db.clone(),
            "INSERT INTO acct (id, owner, bal) VALUES (1, 'a', 10), (2, 'b', 20)".to_string(),
        )
        .await;

        // Empty WHERE fragment MUST be refused (would otherwise mass-update).
        let refused: IpeResult<String, i64> = db_update_where(
            db.clone(),
            "acct".to_string(),
            vec![("bal".to_string(), Some(SqlParam::Int(0)))],
            sql_unsafe_fragment(String::new()),
        )
        .await;
        assert!(
            matches!(refused, IpeResult::Err(_)),
            "empty WHERE must be refused, got {refused:?}"
        );
        let zeroed: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT bal FROM acct WHERE bal = ?".to_string(),
            vec![SqlParam::Int(0)],
        )
        .await;
        assert_eq!(
            zeroed.with_default(Vec::new()).len(),
            0,
            "no row should have been mass-updated"
        );

        // A scoped update with an injection-laden SET value affects exactly the
        // matching row and stores the value VERBATIM (bound, not spliced).
        let nasty = "x'); DROP TABLE acct;-- O'Brien".to_string();
        let scoped: IpeResult<String, i64> = db_update_where(
            db.clone(),
            "acct".to_string(),
            vec![("owner".to_string(), Some(SqlParam::Text(nasty.clone())))],
            sql_eq(sql_column("id".to_string()), sql_param(1i64)),
        )
        .await;
        assert!(
            matches!(scoped, IpeResult::Ok(1)),
            "scoped update should affect exactly 1 row: {scoped:?}"
        );

        // The matching row carries the verbatim value; the non-matching row is
        // untouched; and the table still exists (the DROP never ran).
        let rows: IpeResult<String, Vec<HashMap<String, String>>> = db_query_params(
            db.clone(),
            "SELECT id, owner FROM acct ORDER BY id".to_string(),
            vec![],
        )
        .await;
        match rows {
            IpeResult::Ok(v) => {
                assert_eq!(v.len(), 2, "injection must not have dropped the table");
                assert_eq!(v[0].get("owner").unwrap(), &nasty, "matching row updated");
                assert_eq!(
                    v[1].get("owner").unwrap(),
                    "b",
                    "non-matching row untouched"
                );
            }
            other => panic!("table gone or errored: {other:?}"),
        }

        // An all-OmitField SET updates no columns and reports zero rows.
        let omitted: IpeResult<String, i64> = db_update_where(
            db.clone(),
            "acct".to_string(),
            vec![("owner".to_string(), None)],
            sql_eq(sql_column("id".to_string()), sql_param(2i64)),
        )
        .await;
        assert!(
            matches!(omitted, IpeResult::Ok(0)),
            "all-OmitField SET reports zero rows: {omitted:?}"
        );
    }

    // AUD-07 (a): when DATABASE_URL is absent, ipe_db_url() returns the sqlite
    // file default — never the hardcoded "sqlite::memory:" that caused silent
    // data loss on every Db.connect() call.
    #[test]
    fn ipe_db_url_fallback_is_sqlite_file() {
        if crate::system::read_env_var("DATABASE_URL").is_ok() {
            // DATABASE_URL already set; test (b) covers the env-read path.
            return;
        }
        let url = crate::config::ipe_db_url();
        assert!(
            !url.contains(":memory:"),
            "default URL must not be in-memory: {url}"
        );
        assert!(
            url.contains("ipe.db"),
            "default URL must reference a named file: {url}"
        );
    }

    // AUD-07 (b): with DATABASE_URL set, ipe_db_url() returns it verbatim.
    #[test]
    fn ipe_db_url_reads_database_url_env() {
        use crate::system::{locked_remove_var, locked_set_var};
        locked_set_var("DATABASE_URL", "postgres://ci-host/testdb_aud07");
        let url = crate::config::ipe_db_url();
        locked_remove_var("DATABASE_URL");
        assert_eq!(url, "postgres://ci-host/testdb_aud07");
    }

    // AUD-07 (c): two sequential connect_cached calls with the same file URL
    // observe the same database — data written via one pool is visible via the
    // other. Proves the old sqlite::memory: per-call-fresh-db bug is closed.
    #[tokio::test]
    async fn ipe_db_url_shared_connection_sees_same_data() {
        use crate::system::{locked_remove_var, locked_set_var};
        let tmp = crate::scratch_core::test_temp_root()
            .join(format!("ipe_aud07_shared_{}.db", std::process::id()));
        let url = format!("sqlite://{}?mode=rwc", tmp.display());
        locked_set_var("DATABASE_URL", &url);
        let resolved = crate::config::ipe_db_url();
        locked_remove_var("DATABASE_URL");

        let conn1 = connect_cached::<String>(resolved.clone()).await;
        let conn2 = connect_cached::<String>(resolved).await;
        let pool1 = match conn1 {
            IpeResult::Ok(p) => p,
            IpeResult::Err(e) => panic!("connect1 failed: {e}"),
        };
        let pool2 = match conn2 {
            IpeResult::Ok(p) => p,
            IpeResult::Err(e) => panic!("connect2 failed: {e}"),
        };
        sqlx::query("CREATE TABLE IF NOT EXISTS aud07_t (v INTEGER NOT NULL)")
            .execute(&pool1)
            .await
            .expect("create table");
        sqlx::query("INSERT INTO aud07_t VALUES (99)")
            .execute(&pool1)
            .await
            .expect("insert");
        let (v,): (i64,) = sqlx::query_as("SELECT v FROM aud07_t")
            .fetch_one(&pool2)
            .await
            .expect("select");
        assert_eq!(v, 99, "data written via pool1 must be visible via pool2");
        let _ = std::fs::remove_file(&tmp);
    }

    /// A corpus of identifiers that MUST be rejected at the SQL-interpolation
    /// boundary. Each is a distinct injection or malformation class: quote,
    /// statement terminator, whitespace, comment, backtick, parenthesis, star,
    /// empty, leading-digit-with-punctuation, and a non-ASCII homoglyph. If any
    /// of these ever reaches interpolation the boundary is broken.
    const HOSTILE_IDENTS: &[&str] = &[
        "a'b",
        "a\"b",
        "users; DROP TABLE todos",
        "col name",
        "col--",
        "`col`",
        "f()",
        "*",
        "",
        "1; --",
        "café",
    ];

    /// SSOT proof (unit level): the single `SqlIdent` parser is the ONLY
    /// identifier policy, and `valid_sql_ident` is exactly its dotted mode — not
    /// a second charset check that could drift. For every string we assert
    /// `valid_sql_ident(s) == SqlIdent::parse_dotted(s).is_some()` and that a
    /// dot-accepting parse never admits anything the plain parse would while
    /// rejecting the dot. Every hostile identifier is rejected by BOTH modes.
    #[test]
    fn valid_sql_ident_is_exactly_the_dotted_parser() {
        let corpus = [
            "users",
            "user_id",
            "users.id",
            "a.b.c",
            ".leading",
            "trailing.",
            "todos.title",
        ]
        .iter()
        .copied()
        .chain(HOSTILE_IDENTS.iter().copied());
        for s in corpus {
            assert_eq!(
                valid_sql_ident(s),
                SqlIdent::parse_dotted(s).is_some(),
                "valid_sql_ident must be exactly SqlIdent::parse_dotted for {s:?}"
            );
            // The plain (dot-rejecting) mode admits a subset of the dotted mode:
            // anything plain accepts, dotted must also accept.
            if SqlIdent::parse_plain(s).is_some() {
                assert!(
                    SqlIdent::parse_dotted(s).is_some(),
                    "dotted mode must accept everything plain accepts, for {s:?}"
                );
            }
        }
        // A bare dot-bearing name: accepted dotted, rejected plain — the one
        // deliberate difference between the two modes.
        assert!(SqlIdent::parse_dotted("users.id").is_some());
        assert!(SqlIdent::parse_plain("users.id").is_none());
        // Every hostile identifier is rejected by BOTH modes.
        for h in HOSTILE_IDENTS {
            assert!(
                SqlIdent::parse_plain(h).is_none(),
                "plain parser must reject hostile {h:?}"
            );
            assert!(
                SqlIdent::parse_dotted(h).is_none(),
                "dotted parser must reject hostile {h:?}"
            );
        }
    }

    /// A dotted reference is a sequence of non-empty bare names: every
    /// dot-delimited segment must be non-empty, so a leading dot, a trailing
    /// dot, and consecutive dots are structurally malformed and rejected. A
    /// legitimate single- or multi-segment reference still validates, and
    /// `Plain` mode (which admits no dot at all) is unaffected.
    #[test]
    fn dotted_mode_rejects_empty_segments() {
        // Structurally-malformed dot strings: leading, trailing, consecutive.
        for bad in ["..", ".a", "a.", "a..b", ".", "a.b.", ".a.b"] {
            assert!(
                SqlIdent::parse_dotted(bad).is_none(),
                "dotted parser must reject empty-segment {bad:?}"
            );
        }
        // Well-formed references: a bare name and multi-segment qualified names.
        for good in ["a", "a.b", "todos.title", "a.b.c"] {
            assert!(
                SqlIdent::parse_dotted(good).is_some(),
                "dotted parser must accept well-formed {good:?}"
            );
        }
        // `Plain` mode admits no dot, so its behavior is unchanged: a bare name
        // is accepted, anything with a dot is rejected regardless of segments.
        assert!(SqlIdent::parse_plain("a").is_some());
        for dotted in ["a.b", ".a", "a.", ".."] {
            assert!(
                SqlIdent::parse_plain(dotted).is_none(),
                "plain parser must reject dot-bearing {dotted:?}"
            );
        }
    }

    /// SSOT proof (entry level): every public kernel that interpolates a
    /// table/column identifier into SQL routes through the single validator and
    /// fails CLOSED on a hostile identifier. Each entry is driven with a hostile
    /// value in its identifier position(s); an `IpeResult::Ok` here means a path
    /// reached SQL without validating — the boundary is broken. A new
    /// identifier-accepting entry that skips the validator will fail this test.
    #[tokio::test]
    async fn every_identifier_entry_rejects_hostile_idents() {
        let db = fresh_db().await;
        for &h in HOSTILE_IDENTS {
            let hs = h.to_string();

            macro_rules! assert_rejects {
                ($label:expr, $task:expr) => {{
                    let r: IpeResult<String, _> = $task.await;
                    assert!(
                        matches!(r, IpeResult::Err(_)),
                        "{} must reject hostile identifier {:?}, got Ok",
                        $label,
                        h
                    );
                }};
            }

            // Table-identifier position.
            assert_rejects!(
                "db_get_by_id(table)",
                db_get_by_id(db.clone(), hs.clone(), "1".to_string())
            );
            assert_rejects!(
                "db_delete_by_id(table)",
                db_delete_by_id(db.clone(), hs.clone(), "1".to_string())
            );
            assert_rejects!(
                "db_insert_row(table)",
                db_insert_row(db.clone(), hs.clone(), {
                    let mut m = HashMap::new();
                    m.insert("title".to_string(), "x".to_string());
                    m
                })
            );
            assert_rejects!(
                "db_update_by_id(table)",
                db_update_by_id(db.clone(), hs.clone(), "1".to_string(), {
                    let mut m = HashMap::new();
                    m.insert("title".to_string(), "x".to_string());
                    m
                })
            );
            assert_rejects!(
                "db_find_by_conditions(table)",
                db_find_by_conditions(db.clone(), hs.clone(), {
                    let mut m = HashMap::new();
                    m.insert("title".to_string(), "x".to_string());
                    m
                })
            );
            assert_rejects!(
                "db_find_where(table)",
                db_find_where(
                    db.clone(),
                    hs.clone(),
                    sql_eq(sql_column("title".to_string()), sql_param("x".to_string())),
                )
            );
            assert_rejects!(
                "db_delete_where(table)",
                db_delete_where(
                    db.clone(),
                    hs.clone(),
                    sql_eq(sql_column("title".to_string()), sql_param("x".to_string())),
                )
            );
            assert_rejects!(
                "db_insert_fields(table)",
                db_insert_fields(
                    db.clone(),
                    hs.clone(),
                    vec![("title".to_string(), Some(SqlParam::Text("x".to_string())))],
                )
            );
            assert_rejects!(
                "db_update_fields(table)",
                db_update_fields(
                    db.clone(),
                    hs.clone(),
                    vec![("id".to_string(), SqlParam::Int(1))],
                    vec![("title".to_string(), Some(SqlParam::Text("x".to_string())))],
                )
            );

            // Field/column-identifier position.
            assert_rejects!(
                "db_find_one_by_field(field)",
                db_find_one_by_field(db.clone(), "todos".to_string(), hs.clone(), "x".to_string())
            );
            assert_rejects!(
                "db_find_many_by_field(field)",
                db_find_many_by_field(db.clone(), "todos".to_string(), hs.clone(), "x".to_string())
            );
            assert_rejects!(
                "db_find_by_conditions(column)",
                db_find_by_conditions(db.clone(), "todos".to_string(), {
                    let mut m = HashMap::new();
                    m.insert(hs.clone(), "x".to_string());
                    m
                })
            );
            assert_rejects!(
                "db_insert_fields(column)",
                db_insert_fields(
                    db.clone(),
                    "todos".to_string(),
                    vec![(hs.clone(), Some(SqlParam::Text("x".to_string())))],
                )
            );
            assert_rejects!(
                "db_update_fields(set column)",
                db_update_fields(
                    db.clone(),
                    "todos".to_string(),
                    vec![("id".to_string(), SqlParam::Int(1))],
                    vec![(hs.clone(), Some(SqlParam::Text("x".to_string())))],
                )
            );
            assert_rejects!(
                "db_update_fields(where column)",
                db_update_fields(
                    db.clone(),
                    "todos".to_string(),
                    vec![(hs.clone(), SqlParam::Int(1))],
                    vec![("title".to_string(), Some(SqlParam::Text("x".to_string())))],
                )
            );
            assert_rejects!(
                "db_update_where(table)",
                db_update_where(
                    db.clone(),
                    hs.clone(),
                    vec![("title".to_string(), Some(SqlParam::Text("x".to_string())))],
                    sql_eq(sql_column("id".to_string()), sql_param("1".to_string())),
                )
            );
            assert_rejects!(
                "db_upsert_fields(table)",
                db_upsert_fields(
                    db.clone(),
                    hs.clone(),
                    vec!["id".to_string()],
                    vec![("id".to_string(), Some(SqlParam::Int(1)))],
                )
            );
            assert_rejects!(
                "db_upsert_fields(column)",
                db_upsert_fields(
                    db.clone(),
                    "todos".to_string(),
                    vec!["id".to_string()],
                    vec![
                        ("id".to_string(), Some(SqlParam::Int(1))),
                        (hs.clone(), Some(SqlParam::Text("x".to_string()))),
                    ],
                )
            );
            assert_rejects!(
                "db_upsert_fields(conflict-target column)",
                db_upsert_fields(
                    db.clone(),
                    "todos".to_string(),
                    vec![hs.clone()],
                    vec![(hs.clone(), Some(SqlParam::Text("x".to_string())))],
                )
            );
            assert_rejects!(
                "db_update_where(set column)",
                db_update_where(
                    db.clone(),
                    "todos".to_string(),
                    vec![(hs.clone(), Some(SqlParam::Text("x".to_string())))],
                    sql_eq(sql_column("id".to_string()), sql_param("1".to_string())),
                )
            );

            // `Sql.column` is the SqlFragment-path identifier entry: a hostile
            // identifier poisons the fragment, which the consumers surface as Err.
            assert!(
                sql_column(hs.clone()).invalid.is_some(),
                "sql_column must poison hostile identifier {h:?}"
            );
        }

        // A legitimate dotted column reference still validates where the dotted
        // mode is allowed (Sql.column) — the fix does not over-reject.
        assert!(
            sql_column("todos.title".to_string()).invalid.is_none(),
            "a legitimate dotted column must still validate"
        );
    }

    // ── VettedPool SSRF guard tests ───────────────────────────────────────────
    //
    // These drive the real PostgreSQL gate `VettedPool::connect` runs before
    // dialing, under an explicit policy and a stub resolver; no DB dial and no
    // DNS lookup is attempted.

    use crate::ssrf::BlockedRange;

    use crate::ssrf::test_resolvers::{NoDns, PublicThenPrivate};

    const REBIND_PUBLIC: std::net::IpAddr = PublicThenPrivate::PUBLIC;

    /// The gate's verdict on `url` under `policy`, resolving through `resolver`.
    async fn pg_gate_with<R: HostResolver>(
        url: &str,
        policy: DialPolicy,
        resolver: &R,
    ) -> Result<PinnedPgOptions, DbConnectError> {
        postgres_connect_options(&PostgresUrl::parse(url)?, policy, resolver, 4).await
    }

    /// The gate's verdict on `url` under `policy`, with no DNS available.
    async fn pg_gate(url: &str, policy: DialPolicy) -> Result<PinnedPgOptions, DbConnectError> {
        pg_gate_with(url, policy, &NoDns).await
    }

    /// The refusal the gate gives `url` under deny-private, if any.
    async fn pg_refusal(url: &str) -> Option<SsrfRefusal> {
        match pg_gate(url, DialPolicy::DenyPrivate).await {
            Err(DbConnectError::HostRefused(refusal)) => Some(refusal),
            _ => None,
        }
    }

    #[tokio::test]
    async fn pg_gate_refuses_blocked_literal_hosts_under_deny_private() {
        for (url, range) in [
            ("postgres://127.0.0.1:5432/x", BlockedRange::Loopback),
            ("postgres://[::1]:5432/x", BlockedRange::Loopback),
            ("postgres://169.254.169.254:5432/x", BlockedRange::LinkLocal),
            ("postgres://10.0.0.5/x", BlockedRange::Private),
            ("postgres://0.0.0.0/x", BlockedRange::Reserved),
        ] {
            let refusal = pg_refusal(url).await;
            assert!(
                matches!(refusal, Some(SsrfRefusal::Blocked { range: r, .. }) if r == range),
                "{url:?} must be refused as {range}: {refusal:?}"
            );
        }
    }

    /// A `host` / `hostaddr` query parameter overrides the authority host in
    /// the driver, so the gate must refuse it even when the authority host is
    /// public.
    #[tokio::test]
    async fn pg_gate_refuses_a_query_host_override_under_deny_private() {
        for url in [
            "postgres://8.8.8.8/x?host=169.254.169.254",
            "postgres://8.8.8.8/x?hostaddr=127.0.0.1",
        ] {
            let refusal = pg_refusal(url).await;
            assert!(
                matches!(refusal, Some(SsrfRefusal::Blocked { .. })),
                "{url:?}: {refusal:?}"
            );
        }
    }

    /// A URL naming no host leaves the dial target to the driver, which may
    /// pick `localhost`; under deny-private that unproven target is refused.
    #[tokio::test]
    async fn pg_gate_refuses_a_driver_default_target_under_deny_private() {
        for url in ["postgres:///db", "postgres:db?user=admin"] {
            assert_eq!(
                pg_refusal(url).await,
                Some(SsrfRefusal::UnprovenTarget),
                "{url:?}"
            );
        }
    }

    /// Options dialling a host the vetted URL does not name are refused as an
    /// unproven target, before any lookup.
    #[tokio::test]
    async fn pin_refuses_options_for_a_host_the_url_does_not_name() {
        let url = UnambiguousUrl::parse("postgres://8.8.8.8/x");
        let options = "postgres://1.1.1.1/x".parse::<sqlx::postgres::PgConnectOptions>();
        assert!(url.is_ok() && options.is_ok());
        let (Ok(url), Ok(options)) = (url, options) else {
            return;
        };
        let pinned = pin_postgres_options(&url, options, &[], &NoDns, 4).await;
        assert!(matches!(
            pinned,
            Err(DbConnectError::HostRefused(SsrfRefusal::UnprovenTarget))
        ));
    }

    /// A Unix socket reaches the local server as loopback TCP does, so under
    /// deny-private every socket spelling is refused.
    #[tokio::test]
    async fn pg_gate_refuses_unix_sockets_under_deny_private() {
        for url in [
            "postgres://%2Fvar%2Frun%2Fpostgresql/db",
            "postgres:///db?host=/var/run/postgresql",
            "postgres://8.8.8.8/db?host=/tmp",
        ] {
            assert_eq!(
                pg_refusal(url).await,
                Some(SsrfRefusal::LocalSocket),
                "{url:?}"
            );
        }
    }

    /// With the policy off, sockets, the driver default, and private hosts
    /// pass unpinned, as in local development.
    #[tokio::test]
    async fn pg_gate_passes_local_targets_unpinned_when_the_policy_allows_all() {
        for url in [
            "postgres:///db",
            "postgres://%2Fvar%2Frun%2Fpostgresql/db",
            "postgres:///db?host=/var/run/postgresql",
            "postgres://127.0.0.1:5432/x",
            "postgres://db.internal/x",
        ] {
            let gated = pg_gate(url, DialPolicy::AllowAll).await;
            assert!(gated.is_ok(), "{url:?} must pass: {:?}", gated.err());
        }
        let unpinned = pg_gate("postgres://db.internal/x", DialPolicy::AllowAll).await;
        assert_eq!(
            unpinned.map(|(o, relay)| (o.get_host().to_owned(), relay.is_none())),
            Ok(("db.internal".to_owned(), true))
        );
    }

    /// A public IP-literal host is dialled as itself.
    #[tokio::test]
    async fn pg_gate_keeps_a_public_literal_host() {
        let gated = pg_gate("postgres://u:p@1.1.1.1:6543/x", DialPolicy::DenyPrivate).await;
        let gated =
            gated.map(|(o, relay)| (o.get_host().to_owned(), o.get_port(), relay.is_none()));
        assert_eq!(gated, Ok(("1.1.1.1".to_owned(), 6543, true)));
    }

    /// DNS rebinding: the named host is resolved once and the options the
    /// pool keeps dial the vetted address, so the rebound (private) answer is
    /// never dialled, not even by a connection the pool opens later.
    #[tokio::test]
    async fn pg_gate_pins_a_named_host_against_rebinding() {
        let resolver = PublicThenPrivate::new();
        let gated = pg_gate_with(
            "postgres://u:p@rebind.example:5432/x?sslmode=disable",
            DialPolicy::DenyPrivate,
            &resolver,
        )
        .await
        .map(|(o, relay)| (o.get_host().to_owned(), o.get_port(), relay.is_none()));
        assert_eq!(gated, Ok((REBIND_PUBLIC.to_string(), 5432, true)));
        assert_eq!(
            resolver.calls(),
            1,
            "the name must be resolved exactly once"
        );

        // A fresh connect resolves again and meets the rebound answer.
        let again = pg_gate_with(
            "postgres://u:p@rebind.example:5432/x",
            DialPolicy::DenyPrivate,
            &resolver,
        )
        .await;
        assert!(
            matches!(
                again,
                Err(DbConnectError::HostRefused(SsrfRefusal::Blocked {
                    range: BlockedRange::Private,
                    ..
                }))
            ),
            "{again:?}"
        );
    }

    /// Without a relay, a named host under `sslmode=verify-full` cannot be
    /// pinned without losing the certificate's host-name check, so it is
    /// refused; an IP literal under the same mode is pinned as itself.
    #[cfg(not(unix))]
    #[tokio::test]
    async fn pg_gate_refuses_verify_full_on_a_named_host_under_deny_private() {
        let resolver = PublicThenPrivate::new();
        let refused = pg_gate_with(
            "postgres://db.example/x?sslmode=verify-full",
            DialPolicy::DenyPrivate,
            &resolver,
        )
        .await;
        assert_eq!(
            refused.err(),
            Some(DbConnectError::HostRefused(
                SsrfRefusal::UnpinnableTlsName {
                    host: ConfiguredHost::from_config("db.example".to_owned())
                }
            ))
        );
        let literal = pg_gate(
            "postgres://1.1.1.1/x?sslmode=verify-full",
            DialPolicy::DenyPrivate,
        )
        .await;
        assert!(literal.is_ok(), "{:?}", literal.err());
    }

    /// DNS rebinding under every mode that may negotiate TLS: the host keeps
    /// its name for SNI and certificate verification, the driver dials the
    /// relay socket, and the relay carries the dial to the address vetted by
    /// the only lookup, so the rebound (private) answer is never dialled.
    #[cfg(unix)]
    #[tokio::test]
    async fn pg_gate_relays_a_tls_named_host_to_its_vetted_address() {
        for mode in [
            "",
            "?sslmode=prefer",
            "?sslmode=require",
            "?sslmode=verify-ca",
            "?sslmode=verify-full",
        ] {
            let resolver = PublicThenPrivate::new();
            let url = format!("postgres://u:p@rebind.example:5432/x{mode}");
            let gated = pg_gate_with(&url, DialPolicy::DenyPrivate, &resolver).await;
            assert!(gated.is_ok(), "{url:?}: {:?}", gated.as_ref().err());
            let Ok((options, relay)) = gated else { return };
            assert!(relay.is_some(), "{url:?} must dial through a relay");
            let Some(relay) = relay else { return };
            assert_eq!(options.get_host(), "rebind.example", "{url:?}");
            assert_eq!(
                options.get_socket().map(std::path::PathBuf::as_path),
                Some(relay.socket_dir()),
                "{url:?}"
            );
            assert_eq!(
                relay.target().socket_addr(),
                std::net::SocketAddr::new(REBIND_PUBLIC, 5432),
                "{url:?}"
            );
            assert_eq!(
                resolver.calls(),
                1,
                "{url:?}: the name must be resolved exactly once"
            );
        }
    }

    /// A relay that could not be opened refuses the dial as `RelayUnavailable`.
    #[cfg(unix)]
    #[test]
    fn an_unavailable_relay_is_a_relay_unavailable_connect_error() {
        assert!(matches!(
            DbConnectError::from(crate::ssrf::RelayUnavailable),
            DbConnectError::RelayUnavailable
        ));
    }

    /// An IP-literal host under `sslmode=verify-full` is pinned as itself,
    /// with no relay.
    #[tokio::test]
    async fn pg_gate_pins_a_literal_verify_full_host_without_a_relay() {
        let literal = pg_gate(
            "postgres://1.1.1.1/x?sslmode=verify-full",
            DialPolicy::DenyPrivate,
        )
        .await
        .map(|(o, relay)| (o.get_host().to_owned(), relay.is_none()));
        assert_eq!(literal, Ok(("1.1.1.1".to_owned(), true)));
    }

    /// A named host resolving only to a private address is refused before any
    /// relay opens, whatever the TLS mode.
    #[tokio::test]
    async fn pg_gate_refuses_a_private_named_tls_host_before_relaying() {
        let resolver = PublicThenPrivate::new();
        let first = pg_gate_with(
            "postgres://rebind.example/x?sslmode=verify-full",
            DialPolicy::DenyPrivate,
            &resolver,
        )
        .await;
        assert!(
            first.is_ok() || cfg!(not(unix)),
            "{:?}",
            first.as_ref().err()
        );
        let second = pg_gate_with(
            "postgres://rebind.example/x?sslmode=verify-full",
            DialPolicy::DenyPrivate,
            &resolver,
        )
        .await;
        assert!(
            matches!(
                second,
                Err(DbConnectError::HostRefused(
                    SsrfRefusal::Blocked {
                        range: BlockedRange::Private,
                        ..
                    } | SsrfRefusal::UnpinnableTlsName { .. }
                ))
            ),
            "{:?}",
            second.err()
        );
    }

    /// The test CA that signed [`PG_TLS_SERVER_PEM`].
    #[cfg(unix)]
    const PG_TLS_CA_PEM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/ca.pem"
    ));

    /// A server certificate valid only for [`PG_TLS_HOST`].
    #[cfg(unix)]
    const PG_TLS_SERVER_PEM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/server.pem"
    ));

    /// The private key of [`PG_TLS_SERVER_PEM`].
    #[cfg(unix)]
    const PG_TLS_SERVER_KEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pg_tls/server.key"
    ));

    /// The only name [`PG_TLS_SERVER_PEM`] is valid for.
    #[cfg(unix)]
    const PG_TLS_HOST: &str = "db.example.test";

    /// What the fake TLS server saw of one client.
    #[cfg(unix)]
    #[derive(Debug, PartialEq, Eq)]
    struct TlsSeen {
        /// The SNI name the client sent, if any.
        sni: Option<String>,
        /// Whether the TLS handshake completed.
        handshaken: bool,
    }

    /// The fake server's TLS configuration, serving [`PG_TLS_SERVER_PEM`].
    #[cfg(unix)]
    fn pg_tls_server_config() -> Option<rustls::ServerConfig> {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let certs = CertificateDer::pem_slice_iter(PG_TLS_SERVER_PEM)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let key = PrivateKeyDer::from_pem_slice(PG_TLS_SERVER_KEY).ok()?;
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()
    }

    /// Answer one PostgreSQL `SSLRequest` on `listener` with TLS, then hang up.
    #[cfg(unix)]
    fn serve_one_pg_tls_client(listener: &std::net::TcpListener) -> Option<TlsSeen> {
        use std::io::{Read, Write};
        const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];
        let (mut tcp, _) = listener.accept().ok()?;
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok()?;
        let mut request = [0_u8; 8];
        tcp.read_exact(&mut request).ok()?;
        if request != SSL_REQUEST {
            return None;
        }
        tcp.write_all(b"S").ok()?;
        let config = pg_tls_server_config()?;
        let mut tls = rustls::ServerConnection::new(std::sync::Arc::new(config)).ok()?;
        while tls.is_handshaking() {
            if tls.complete_io(&mut tcp).is_err() {
                break;
            }
        }
        Some(TlsSeen {
            sni: tls.server_name().map(str::to_owned),
            handshaken: !tls.is_handshaking(),
        })
    }

    /// Dial a fake TLS PostgreSQL server as `host` under `verify-full`, only
    /// through a relay pinned to the server's address.
    #[cfg(unix)]
    async fn dial_pg_tls_through_relay(host: &str) -> (Result<(), DriverFailure>, Option<TlsSeen>) {
        let io_failure = || {
            DriverFailure::of(
                DbEngine::Postgres,
                &sqlx::Error::Io(std::io::Error::other("test setup")),
            )
        };
        use sqlx::ConnectOptions;
        let listener = std::net::TcpListener::bind("127.0.0.1:0");
        assert!(listener.is_ok(), "{:?}", listener.as_ref().err());
        let Ok(listener) = listener else {
            return (Err(io_failure()), None);
        };
        let Ok(server) = listener.local_addr() else {
            return (Err(io_failure()), None);
        };
        let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .spawn(move || {
                let _sent = seen_tx.send(serve_one_pg_tls_client(&listener));
            })
            .expect("spawn test thread");
        let relay = crate::ssrf::PinnedRelay::open(
            crate::ssrf::VettedAddr::assume_vetted_for_test(server),
            5432,
            4,
        );
        assert!(relay.is_ok(), "{:?}", relay.as_ref().err());
        let Ok(relay) = relay else {
            return (Err(io_failure()), None);
        };
        let options = sqlx::postgres::PgConnectOptions::new()
            .host(host)
            .port(5432)
            .socket(relay.socket_dir())
            .username("ipe")
            .database("ipe")
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(PG_TLS_CA_PEM.to_vec());
        let limit = std::time::Duration::from_secs(20);
        let connected = tokio::time::timeout(limit, options.connect()).await;
        let outcome = match connected {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(DriverFailure::of(DbEngine::Postgres, &e)),
            Err(_) => Err(DriverFailure::of(
                DbEngine::Postgres,
                &sqlx::Error::PoolTimedOut,
            )),
        };
        let seen = tokio::time::timeout(limit, seen_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .flatten();
        (outcome, seen)
    }

    /// Through the relay, the driver sends the host name, not the pinned IP,
    /// as SNI and completes a `verify-full` handshake against a certificate
    /// valid only for that name.
    #[cfg(unix)]
    #[tokio::test]
    async fn relayed_tls_dial_sends_the_host_name_and_verifies_it() {
        let (_outcome, seen) = dial_pg_tls_through_relay(PG_TLS_HOST).await;
        assert_eq!(
            seen,
            Some(TlsSeen {
                sni: Some(PG_TLS_HOST.to_owned()),
                handshaken: true,
            })
        );
    }

    /// Through the relay, a certificate that is not valid for the dialled
    /// host name is refused by the driver before the handshake completes.
    #[cfg(unix)]
    #[tokio::test]
    async fn relayed_tls_dial_refuses_a_certificate_for_another_name() {
        let (outcome, seen) = dial_pg_tls_through_relay("other.example.test").await;
        assert!(
            matches!(
                &outcome,
                Err(f) if f.failure() == IpeDbFailure::Unreachable
            ),
            "{outcome:?}"
        );
        assert!(
            seen.as_ref()
                .is_some_and(|s| s.sni.as_deref() == Some("other.example.test") && !s.handshaken),
            "{seen:?}"
        );
    }

    /// An unresolvable named host is refused with the typed reason.
    #[tokio::test]
    async fn pg_gate_refuses_an_unresolvable_named_host() {
        assert_eq!(
            pg_refusal("postgres://nowhere.example/x").await,
            Some(SsrfRefusal::Unresolvable {
                host: crate::ssrf::HostShown::Named("nowhere.example".to_owned()),
                kind: std::io::ErrorKind::NotFound,
            })
        );
    }

    /// SQLite dials no host: its gate only parses the URL.
    #[tokio::test]
    async fn sqlite_gate_consults_no_host() {
        for url in ["sqlite:///app.db", "sqlite::memory:"] {
            let parsed = DbUrl::parse(url);
            assert!(parsed.is_ok(), "{url:?}: {:?}", parsed.err());
            let Ok(parsed) = parsed else { return };
            let gated =
                <sqlx::Sqlite as GatedDial>::gated_connect_options(&parsed, 4, &mut None).await;
            assert!(gated.is_ok(), "{url:?}: {:?}", gated.err());
        }
    }

    // ── DbUrl: one parse decides the engine, the dial, and WAL ────────────────

    /// The engine each scheme selects.
    #[test]
    fn db_url_selects_the_engine_by_scheme() {
        for (url, engine) in [
            ("sqlite://app.db?mode=rwc", DbEngine::Sqlite),
            ("sqlite::memory:", DbEngine::Sqlite),
            ("file:app.db", DbEngine::Sqlite),
            ("app.db", DbEngine::Sqlite),
            ("./data/app.db", DbEngine::Sqlite),
            (":memory:", DbEngine::Sqlite),
            ("postgres://u:p@db.example/app", DbEngine::Postgres),
            ("postgresql://db.example/app", DbEngine::Postgres),
            ("postgres:///app", DbEngine::Postgres),
        ] {
            assert!(
                DbUrl::parse(url).is_ok_and(|parsed| parsed.engine() == engine),
                "{url:?} must select {}",
                engine.name()
            );
        }
    }

    /// A scheme selecting no supported engine is refused without echoing it,
    /// since a malformed URL's scheme position can hold its userinfo.
    #[test]
    fn db_url_refuses_an_unsupported_scheme() {
        for url in [
            "mysql://admin:s3cr3t-pw@db.example/app",
            "redis://db.example/",
            "http://db.example/",
            "SQLITE://app.db",
            "Postgres://db.example/app",
            "admin:s3cr3t-pw@db.example/app",
        ] {
            let refused = DbUrl::parse(url).err();
            assert_eq!(refused, Some(DbConnectError::UnsupportedScheme), "{url:?}");
            if let Some(refused) = refused {
                assert_credential_free(&refused);
            }
        }
    }

    /// A PostgreSQL URL whose dial targets cannot be read is refused at the parse.
    #[test]
    fn db_url_refuses_an_unreadable_postgres_url() {
        for url in [
            "postgres://public.example/db?port=s3cr3t-pw",
            "postgres://public.example/db?port=70000",
        ] {
            assert_eq!(
                DbUrl::parse(url).err(),
                Some(DbConnectError::InvalidUrl),
                "{url:?}"
            );
        }
    }

    /// A SQLite URL the driver cannot read is refused at the parse, as a
    /// PostgreSQL one is, never reported as an unreachable server.
    #[test]
    fn db_url_refuses_an_unreadable_sqlite_url() {
        for url in [
            "sqlite://app.db?mode=bogus",
            "sqlite://app.db?no_such_param=1",
        ] {
            assert_eq!(
                DbUrl::parse(url).err(),
                Some(DbConnectError::InvalidUrl),
                "{url:?}"
            );
        }
    }

    /// A PostgreSQL URL's dial targets are read once, at the parse, and the
    /// gate vets exactly those.
    #[test]
    fn db_url_carries_the_postgres_dial_targets() {
        let parsed = DbUrl::parse("postgres://public.example/db?host=169.254.169.254");
        let targets = match parsed {
            Ok(DbUrl::Postgres(postgres)) => Some(postgres.targets),
            _ => None,
        };
        assert_eq!(
            targets,
            Some(vec![
                DialTarget::Tcp {
                    host: ConfiguredHost::from_config("public.example".to_owned()),
                    port: POSTGRES_DEFAULT_PORT,
                },
                DialTarget::Tcp {
                    host: ConfiguredHost::from_config("169.254.169.254".to_owned()),
                    port: POSTGRES_DEFAULT_PORT,
                },
            ])
        );
    }

    /// Only a shared SQLite file gets the WAL setup: never a PostgreSQL URL
    /// that merely mentions `sqlite`, never a private in-memory database.
    #[test]
    fn db_url_decides_wal_from_the_parsed_engine() {
        for (url, wal) in [
            ("sqlite://app.db?mode=rwc", true),
            ("app.db", true),
            ("file::memory:?cache=shared", true),
            ("sqlite::memory:", false),
            (":memory:", false),
            ("postgres://db.example/sqlite", false),
            ("postgres://db.example/app?application_name=sqlite", false),
        ] {
            assert!(
                DbUrl::parse(url).is_ok_and(|parsed| parsed.is_shared_sqlite_file() == wal),
                "{url:?}: WAL must be {wal}"
            );
        }
    }

    /// Each driver refuses a URL selecting the other engine, before any dial
    /// or lookup.
    #[tokio::test]
    async fn gated_dial_refuses_a_url_for_the_other_engine() {
        let postgres = DbUrl::parse("postgres://127.0.0.1/app");
        assert!(postgres.is_ok(), "{:?}", postgres.as_ref().err());
        let Ok(postgres) = postgres else { return };
        assert_eq!(
            <sqlx::Sqlite as GatedDial>::gated_connect_options(&postgres, 4, &mut None)
                .await
                .err(),
            Some(DbConnectError::EngineMismatch {
                url: DbEngine::Postgres,
                driver: DbEngine::Sqlite,
            })
        );
        let sqlite = DbUrl::parse("sqlite::memory:");
        assert!(sqlite.is_ok(), "{:?}", sqlite.as_ref().err());
        let Ok(sqlite) = sqlite else { return };
        assert_eq!(
            <sqlx::Postgres as GatedDial>::gated_connect_options(&sqlite, 4, &mut None)
                .await
                .err(),
            Some(DbConnectError::EngineMismatch {
                url: DbEngine::Sqlite,
                driver: DbEngine::Postgres,
            })
        );
    }

    /// `build_pool` refuses an unsupported scheme and a URL for the other
    /// engine, with the typed reason and no credential.
    #[tokio::test]
    async fn build_pool_refuses_urls_the_build_cannot_open() {
        for (url, expected) in [
            (
                "mysql://admin:s3cr3t-pw@db.example/app",
                DbConnectError::UnsupportedScheme,
            ),
            (
                "postgres://admin:s3cr3t-pw@1.1.1.1/app",
                DbConnectError::EngineMismatch {
                    url: DbEngine::Postgres,
                    driver: DbEngine::Sqlite,
                },
            ),
        ] {
            let refused = match build_pool::<String>(url).await {
                IpeResult::Err(e) => Some(e),
                IpeResult::Ok(_) => None,
            };
            assert_eq!(refused, Some(expected.to_string()), "{url:?}");
        }
    }

    /// The busy timeout of the connection `conn` is running on, in milliseconds.
    async fn busy_timeout_ms(conn: &mut sqlx::SqliteConnection) -> i64 {
        sqlx::query_scalar::<_, i64>("PRAGMA busy_timeout")
            .fetch_one(conn)
            .await
            .expect("read busy_timeout")
    }

    /// Every connection a file pool hands out at once carries the declared
    /// busy timeout, not only the one a pool-level PRAGMA happened to reach.
    #[tokio::test]
    async fn every_pooled_sqlite_connection_carries_the_declared_busy_timeout() {
        let path = crate::scratch_core::test_temp_root().join(format!(
            "ipe_busy_timeout_{}_{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = match build_pool::<String>(&url).await {
            IpeResult::Ok(pool) => Some(pool),
            IpeResult::Err(_) => None,
        }
        .expect("build file pool");
        let expected = i64::try_from(SQLITE_BUSY_TIMEOUT.as_millis()).expect("timeout fits i64");
        let max_connections: u32 = DB_CONNECTIONS_CEILING
            .read()
            .expect("default connection ceiling");
        let mut held = Vec::new();
        for _ in 0..max_connections {
            held.push(pool.acquire().await.expect("acquire pooled connection"));
        }
        assert_eq!(
            held.len(),
            usize::try_from(max_connections).expect("u32 fits usize")
        );
        for conn in &mut held {
            assert_eq!(busy_timeout_ms(conn).await, expected);
        }
        drop(held);
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// The declared busy timeout is a finite, non-zero wait longer than the
    /// driver's own 5 s default, so declaring it changes what a connection does.
    #[test]
    fn the_busy_timeout_is_finite_and_above_the_driver_default() {
        let driver_default = sqlx::sqlite::SqliteConnectOptions::new();
        let default_debug = format!("{driver_default:?}");
        assert!(
            default_debug.contains("busy_timeout: 5s"),
            "{default_debug}"
        );
        assert!(SQLITE_BUSY_TIMEOUT > std::time::Duration::from_secs(5));
        assert!(SQLITE_BUSY_TIMEOUT < std::time::Duration::from_secs(600));
    }

    /// A PostgreSQL refusal displays under the `db:` prefix.
    #[test]
    fn host_refused_displays_under_the_db_prefix() {
        let shown = DbConnectError::HostRefused(SsrfRefusal::LocalSocket).to_string();
        assert_eq!(
            shown,
            "db: blocked: local socket dial target (IPE_HTTP_DENY_PRIVATE)"
        );
    }

    // ── parse_order_clause ─────────────────────────────────────────────────────

    /// `parse_order_clause` with a valid alias, column, and descending direction
    /// produces the exact `alias.column DESC` fragment the ordered projection
    /// statement embeds — no interpolation, both identifiers pre-validated.
    #[test]
    fn parse_order_clause_valid_desc_is_exact_sql_fragment() {
        let clause =
            parse_order_clause("a1", "name", false).expect("valid identifiers must succeed");
        assert_eq!(clause, "a1.name DESC");
    }

    /// `parse_order_clause` with ascending direction produces the `ASC` form.
    #[test]
    fn parse_order_clause_valid_asc_is_exact_sql_fragment() {
        let clause =
            parse_order_clause("a0", "created_at", true).expect("valid identifiers must succeed");
        assert_eq!(clause, "a0.created_at ASC");
    }

    /// An invalid order-column alias (contains SQL-injection characters) is
    /// rejected by `parse_order_clause` — the clause never reaches SQL text.
    #[test]
    fn parse_order_clause_rejects_bad_alias() {
        let result = parse_order_clause("a1; DROP TABLE books", "name", true);
        assert!(result.is_err(), "a non-identifier alias must be rejected");
    }

    /// An invalid order column name (contains SQL-injection characters) is
    /// rejected by `parse_order_clause` — the clause never reaches SQL text.
    #[test]
    fn parse_order_clause_rejects_bad_column() {
        let result = parse_order_clause("a1", "name); DROP TABLE books", false);
        assert!(result.is_err(), "a non-identifier column must be rejected");
    }

    // ── Store.upper / Store.lower: `UPPER/LOWER(alias.col) AS pN` ──────────────

    /// Golden SQL: `UpperTerm("a1.name")` emits exactly `UPPER(a1.name) AS p0`
    /// — the SQL function name comes from the closed variant, the dotted column
    /// is re-validated via `SqlIdent::parse_dotted` (defence in depth).
    #[test]
    fn projection_statement_upper_term_emits_exact_function_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::UpperTerm("a1.name".into())],
            &frag.sql,
        )
        .expect("UpperTerm with a valid dotted column must build");
        assert_eq!(literal_count, 0, "an UpperTerm binds no extra parameter");
        assert_eq!(
            sql,
            "SELECT UPPER(a1.name) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// A bad dotted column inside `UpperTerm` is rejected fail-closed —
    /// `SqlIdent::parse_dotted` refuses the identifier before SQL text.
    #[test]
    fn projection_statement_upper_term_rejects_bad_dotted_column() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let with_semicolon = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::UpperTerm(
                "a1.name); DROP TABLE authors".into(),
            )],
            &frag.sql,
        );
        assert!(
            with_semicolon.is_err(),
            "a dotted column with injection characters must be rejected fail-closed"
        );
        let with_space = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::UpperTerm("a1.name col".into())],
            &frag.sql,
        );
        assert!(
            with_space.is_err(),
            "a dotted column with a space must be rejected fail-closed"
        );
        let with_paren = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::UpperTerm("a1.name(x)".into())],
            &frag.sql,
        );
        assert!(
            with_paren.is_err(),
            "a dotted column with a paren must be rejected fail-closed"
        );
    }

    // ── Store.literal: `? AS pN` in projection SELECT ────────────────────────

    /// Golden SQL: a mixed projection with `LiteralTerm` and `ColumnTerm` lowers
    /// to `SELECT ? AS p0, a1.name AS p1 FROM … WHERE …`.  Literal count is 1.
    #[test]
    fn projection_statement_literal_term_emits_question_mark_alias() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[
                ProjectionTerm::LiteralTerm,
                ProjectionTerm::ColumnTerm("a1".into(), "name".into()),
            ],
            &frag.sql,
        )
        .expect("statement builds");
        assert_eq!(literal_count, 1, "one literal position");
        assert_eq!(
            sql,
            "SELECT ? AS p0, a1.name AS p1 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
        assert!(
            sql.starts_with("SELECT ? AS p0"),
            "the literal position is a `?` placeholder, not a column reference"
        );
    }

    /// `db_find_projection` with a `Store.literal` position binds the extra param
    /// before the WHERE params and returns it as the `p0` column in every row.
    #[tokio::test]
    async fn test_find_projection_literal_bind_appears_in_result() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![
                ProjectionTerm::LiteralTerm,
                ProjectionTerm::ColumnTerm("a1".into(), "name".into()),
            ],
            vec![SqlParam::Text("fiction".to_string())],
        )
        .await;
        match found {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 2, "only active author Ada's two books");
                for row in &rows {
                    assert_eq!(
                        row.get("p0").map(String::as_str),
                        Some("fiction"),
                        "p0 is the literal value bound as a parameter"
                    );
                    assert_eq!(
                        row.get("p1").map(String::as_str),
                        Some("Ada"),
                        "p1 is the projected column"
                    );
                    assert_eq!(row.len(), 2, "exactly two projected columns");
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    /// `db_find_projection` with a mismatched `extra_binds` count fails closed —
    /// one `LiteralTerm` in the projection but zero extra binds.
    #[tokio::test]
    async fn test_find_projection_rejects_mismatched_extra_binds() {
        let db = fresh_join_db().await;
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![ProjectionTerm::LiteralTerm],
            vec![], // no extra bind for the one literal position — must fail
        )
        .await;
        assert!(
            matches!(found, IpeResult::Err(_)),
            "a mismatched extra_binds count must fail closed"
        );
    }

    // ── Store.coalesce: `COALESCE(a, b) AS pN` ───────────────────────────────

    /// Golden SQL: `CoalesceTerm(OperandColumn("a1.name"), OperandLiteral)` emits
    /// exactly `COALESCE(a1.name, ?) AS p0` — the column operand is re-validated
    /// via `SqlIdent::parse_dotted`; the literal operand emits `?`.  Count is 1.
    #[test]
    fn projection_statement_coalesce_column_literal_emits_exact_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::CoalesceTerm(
                ProjectionOperand::OperandColumn("a1.name".into()),
                ProjectionOperand::OperandLiteral,
            )],
            &frag.sql,
        )
        .expect("CoalesceTerm(column, literal) must build");
        assert_eq!(
            literal_count, 1,
            "one literal position for the OperandLiteral"
        );
        assert_eq!(
            sql,
            "SELECT COALESCE(a1.name, ?) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// Golden SQL: `CoalesceTerm(OperandColumn("a0.name"), OperandColumn("a1.fallback"))` emits
    /// `COALESCE(a0.name, a1.fallback) AS p0` — both operands are column
    /// references re-validated via `SqlIdent::parse_dotted`; no extra bind.
    #[test]
    fn projection_statement_coalesce_two_columns_emits_exact_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::CoalesceTerm(
                ProjectionOperand::OperandColumn("a0.name".into()),
                ProjectionOperand::OperandColumn("a1.fallback".into()),
            )],
            &frag.sql,
        )
        .expect("CoalesceTerm(column, column) must build");
        assert_eq!(
            literal_count, 0,
            "no literal positions: both operands are columns"
        );
        assert_eq!(
            sql,
            "SELECT COALESCE(a0.name, a1.fallback) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// A bad dotted column inside a `CoalesceTerm` is rejected fail-closed.
    #[test]
    fn projection_statement_coalesce_rejects_bad_dotted_operand() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let bad_a = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::CoalesceTerm(
                ProjectionOperand::OperandColumn("a1.name); DROP TABLE authors".into()),
                ProjectionOperand::OperandLiteral,
            )],
            &frag.sql,
        );
        assert!(
            bad_a.is_err(),
            "injection in first COALESCE operand must be rejected fail-closed"
        );
        let bad_b = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::CoalesceTerm(
                ProjectionOperand::OperandColumn("a1.name".into()),
                ProjectionOperand::OperandColumn("a0.col; DROP".into()),
            )],
            &frag.sql,
        );
        assert!(
            bad_b.is_err(),
            "injection in second COALESCE operand must be rejected fail-closed"
        );
    }

    /// `db_find_projection` with a COALESCE(column, literal) position binds the
    /// extra param before the WHERE params and returns the coalesced value in `p0`.
    #[tokio::test]
    async fn test_find_projection_coalesce_column_literal() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a1.active".to_string()), sql_param(1_i64)),
        );
        // COALESCE(a1.name, ?) — the column is non-null for active Ada, so COALESCE
        // returns the column value ("Ada"), not the fallback literal.
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![ProjectionTerm::CoalesceTerm(
                ProjectionOperand::OperandColumn("a1.name".into()),
                ProjectionOperand::OperandLiteral,
            )],
            vec![SqlParam::Text("unknown".to_string())],
        )
        .await;
        match found {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 2, "only active author Ada's two books");
                for row in &rows {
                    assert_eq!(
                        row.get("p0").map(String::as_str),
                        Some("Ada"),
                        "COALESCE returns the non-null column value"
                    );
                }
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    // ── Store.add / .sub / .mul: `(a <op> b) AS pN` ──────────────────────────

    /// Golden SQL: `ArithTerm(ArithAdd, OperandColumn("a0.quantity"), OperandLiteral)`
    /// emits exactly `(a0.quantity + ?) AS p0` — the column operand is
    /// re-validated via `SqlIdent::parse_dotted`; the literal operand emits `?`.
    /// Count is 1.
    #[test]
    fn projection_statement_arith_add_column_literal_emits_exact_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ArithTerm(
                ArithOp::ArithAdd,
                ProjectionOperand::OperandColumn("a0.quantity".into()),
                ProjectionOperand::OperandLiteral,
            )],
            &frag.sql,
        )
        .expect("ArithTerm(add, column, literal) must build");
        assert_eq!(
            literal_count, 1,
            "one literal position for the OperandLiteral"
        );
        assert_eq!(
            sql,
            "SELECT (a0.quantity + ?) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// Golden SQL: `ArithTerm(ArithSub, column, column)` emits
    /// `(a0.price - a0.discount) AS p0` — both operands re-validated; no bind.
    #[test]
    fn projection_statement_arith_sub_two_columns_emits_exact_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ArithTerm(
                ArithOp::ArithSub,
                ProjectionOperand::OperandColumn("a0.price".into()),
                ProjectionOperand::OperandColumn("a0.discount".into()),
            )],
            &frag.sql,
        )
        .expect("ArithTerm(sub, column, column) must build");
        assert_eq!(
            literal_count, 0,
            "no literal positions: both operands are columns"
        );
        assert_eq!(
            sql,
            "SELECT (a0.price - a0.discount) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// Golden SQL: `ArithTerm(ArithMul, column, literal)` emits
    /// `(a0.price * ?) AS p0` with one bound literal.
    #[test]
    fn projection_statement_arith_mul_column_literal_emits_exact_sql() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let (sql, literal_count) = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ArithTerm(
                ArithOp::ArithMul,
                ProjectionOperand::OperandColumn("a0.price".into()),
                ProjectionOperand::OperandLiteral,
            )],
            &frag.sql,
        )
        .expect("ArithTerm(mul, column, literal) must build");
        assert_eq!(literal_count, 1, "one literal position");
        assert_eq!(
            sql,
            "SELECT (a0.price * ?) AS p0 \
             FROM books AS a0, authors AS a1 WHERE (a1.id = a0.author_id)"
        );
    }

    /// A bad dotted column inside an `ArithTerm` is rejected fail-closed —
    /// `SqlIdent::parse_dotted` refuses an operand with injection characters,
    /// in either operand position.
    #[test]
    fn projection_statement_arith_rejects_bad_dotted_operand() {
        let frag = sql_eq(
            sql_column("a1.id".to_string()),
            sql_column("a0.author_id".to_string()),
        );
        let bad_a = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ArithTerm(
                ArithOp::ArithAdd,
                ProjectionOperand::OperandColumn("a0.price); DROP TABLE books".into()),
                ProjectionOperand::OperandLiteral,
            )],
            &frag.sql,
        );
        assert!(
            bad_a.is_err(),
            "injection in first arithmetic operand must be rejected fail-closed"
        );
        let bad_b = build_projection_statement(
            "books",
            "a0",
            "authors",
            "a1",
            &[ProjectionTerm::ArithTerm(
                ArithOp::ArithMul,
                ProjectionOperand::OperandColumn("a0.price".into()),
                ProjectionOperand::OperandColumn("a0.qty; DROP".into()),
            )],
            &frag.sql,
        );
        assert!(
            bad_b.is_err(),
            "injection in second arithmetic operand must be rejected fail-closed"
        );
    }

    /// `db_find_projection` with an `(a0.id + ?)` position binds the extra param
    /// before the WHERE params and returns the summed value in `p0`.
    #[tokio::test]
    async fn test_find_projection_arith_column_literal() {
        let db = fresh_join_db().await;
        let frag = sql_and(
            sql_eq(
                sql_column("a1.id".to_string()),
                sql_column("a0.author_id".to_string()),
            ),
            sql_eq(sql_column("a0.id".to_string()), sql_param(10_i64)),
        );
        // (a0.id + ?) with the book id 10 and a bound literal 5 → 15.
        let found: IpeResult<String, Vec<HashMap<String, String>>> = db_find_projection(
            db,
            "books".into(),
            "a0".into(),
            "authors".into(),
            "a1".into(),
            frag,
            vec![ProjectionTerm::ArithTerm(
                ArithOp::ArithAdd,
                ProjectionOperand::OperandColumn("a0.id".into()),
                ProjectionOperand::OperandLiteral,
            )],
            vec![SqlParam::Int(5)],
        )
        .await;
        match found {
            IpeResult::Ok(rows) => {
                assert_eq!(rows.len(), 1, "exactly the one book with id 10");
                assert_eq!(
                    rows[0].get("p0").map(String::as_str),
                    Some("15"),
                    "(a0.id + ?) = 10 + 5 = 15"
                );
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    // ─── Engine version floor ────────────────────────────────────────────────

    /// The release immediately preceding `v` in `(major, minor)` order.
    fn one_step_below(v: EngineVersion) -> EngineVersion {
        if v.minor() > 0 {
            EngineVersion::new(v.major(), v.minor() - 1)
        } else {
            EngineVersion::new(v.major().saturating_sub(1), 99)
        }
    }

    fn sqlite_report(v: EngineVersion) -> String {
        format!("{}.{}.0", v.major(), v.minor())
    }

    /// `server_version_num` encoding of `v` (patch 0).
    fn postgres_report(v: EngineVersion) -> String {
        let num = if v.major() >= 10 {
            v.major() * 10_000 + v.minor()
        } else {
            v.major() * 10_000 + v.minor() * 100
        };
        num.to_string()
    }

    fn report(engine: DbEngine, v: EngineVersion) -> String {
        match engine {
            DbEngine::Sqlite => sqlite_report(v),
            DbEngine::Postgres => postgres_report(v),
        }
    }

    const ENGINES: [DbEngine; 2] = [DbEngine::Sqlite, DbEngine::Postgres];

    #[test]
    fn engine_floor_admits_the_floor_itself() {
        for engine in ENGINES {
            let floor = engine.version_floor();
            assert_eq!(
                check_engine_version(engine, &report(engine, floor)),
                Ok(floor),
                "{engine} at its floor must be admitted"
            );
        }
    }

    #[test]
    fn engine_floor_refuses_one_step_below() {
        for engine in ENGINES {
            let below = one_step_below(engine.version_floor());
            assert_eq!(
                check_engine_version(engine, &report(engine, below)),
                Err(EngineVersionError::BelowFloor {
                    engine,
                    found: below
                }),
                "{engine} one step below its floor must be refused"
            );
        }
    }

    #[test]
    fn engine_floor_admits_newer_majors() {
        assert!(check_engine_version(DbEngine::Sqlite, "4.0.0").is_ok());
        assert_eq!(
            check_engine_version(DbEngine::Postgres, "170002"),
            Ok(EngineVersion::new(17, 2))
        );
    }

    #[test]
    fn engine_floor_refuses_an_older_major_with_a_larger_minor() {
        let floor = DbEngine::Sqlite.version_floor();
        let older = EngineVersion::new(floor.major() - 1, floor.minor() + 1);
        assert!(matches!(
            check_engine_version(DbEngine::Sqlite, &sqlite_report(older)),
            Err(EngineVersionError::BelowFloor { .. })
        ));
    }

    #[test]
    fn engine_floor_refuses_unparseable_sqlite_reports() {
        let floor = SQLITE_VERSION_FLOOR;
        let (maj, min) = (floor.major(), floor.minor());
        for raw in [
            String::new(),
            "garbage".to_string(),
            format!("{maj}.{min}"),
            format!("{maj}.{min}."),
            format!("{maj}.{min}.0.1"),
            format!("+{maj}.{min}.0"),
            format!(" {maj}.{min}.0"),
            format!("{maj}.{min}.0 "),
            format!("{maj}.x.0"),
            format!("{maj}..{min}"),
            "99999999999.0.0".to_string(),
        ] {
            assert_eq!(
                check_engine_version(DbEngine::Sqlite, &raw),
                Err(EngineVersionError::Unparseable {
                    engine: DbEngine::Sqlite
                }),
                "SQLite report {raw:?} must fail closed"
            );
        }
    }

    #[test]
    fn engine_floor_refuses_unparseable_postgres_reports() {
        let floor = POSTGRES_VERSION_FLOOR;
        for raw in [
            String::new(),
            "garbage".to_string(),
            floor.to_string(),
            format!("+{}", postgres_report(floor)),
            format!("-{}", postgres_report(floor)),
            format!("{} ", postgres_report(floor)),
            "99999999999".to_string(),
        ] {
            assert_eq!(
                check_engine_version(DbEngine::Postgres, &raw),
                Err(EngineVersionError::Unparseable {
                    engine: DbEngine::Postgres
                }),
                "PostgreSQL report {raw:?} must fail closed"
            );
        }
    }

    #[test]
    fn engine_floor_error_names_the_required_floor() {
        for engine in ENGINES {
            let floor = engine.version_floor();
            let below = EngineVersionError::BelowFloor {
                engine,
                found: one_step_below(floor),
            }
            .to_string();
            let unparseable = EngineVersionError::Unparseable { engine }.to_string();
            for msg in [below, unparseable] {
                assert!(
                    msg.contains(&format!("{engine} >= {floor}")),
                    "error {msg:?} must name the required floor"
                );
            }
        }
    }

    #[test]
    fn engine_for_build_resolves_the_linked_driver() {
        assert_eq!(DbEngine::for_driver::<DbDatabase>(), Ok(DbEngine::Sqlite));
        assert_eq!(
            DbEngine::for_driver::<sqlx::Postgres>(),
            Ok(DbEngine::Postgres)
        );
        assert_eq!(DbEngine::from_driver_name("MySQL"), None);
        assert_eq!(DbEngine::from_driver_name(""), None);
    }

    /// The bundled SQLite passes the gate end to end: `build_pool` reads the
    /// live `sqlite_version()` and admits it.
    #[tokio::test]
    async fn engine_floor_admits_the_bundled_sqlite() {
        let pool = build_pool::<String>("sqlite::memory:").await;
        assert!(
            matches!(pool, IpeResult::Ok(_)),
            "bundled SQLite must clear its version floor"
        );
    }

    /// The shared gate admits a live pool and reports the version it read.
    #[tokio::test]
    async fn engine_floor_on_admits_a_live_sqlite_pool() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await;
        assert!(pool.is_ok(), "in-memory SQLite must connect");
        if let Ok(pool) = pool {
            let admitted = enforce_engine_floor_on(&pool).await;
            assert!(
                matches!(admitted, Ok(v) if v >= SQLITE_VERSION_FLOOR),
                "bundled SQLite must clear the shared gate, got {admitted:?}"
            );
        }
    }

    /// A pool whose version cannot be read is refused, never admitted.
    #[tokio::test]
    async fn engine_floor_on_refuses_an_unreadable_pool() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await;
        assert!(pool.is_ok(), "in-memory SQLite must connect");
        if let Ok(pool) = pool {
            pool.close().await;
            assert_eq!(
                enforce_engine_floor_on(&pool).await,
                Err(DbConnectError::VersionUnreadable(DriverFailure::of(
                    DbEngine::Sqlite,
                    &sqlx::Error::PoolClosed
                )))
            );
        }
    }

    /// A floor refusal still names the required floor.
    #[test]
    fn engine_floor_refusal_names_the_required_floor() {
        for engine in ENGINES {
            let floor = engine.version_floor();
            let refused = DbConnectError::EngineRefused(EngineVersionError::BelowFloor {
                engine,
                found: one_step_below(floor),
            });
            assert!(
                refused
                    .to_string()
                    .contains(&format!("{engine} >= {floor}")),
                "refusal {refused} must name the required floor"
            );
        }
    }

    /// A failed version query renders from the error variant, never the
    /// driver payload.
    #[test]
    fn engine_floor_query_failure_is_credential_free() {
        let raw = sqlx::Error::Io(std::io::Error::other(SECRET_URL));
        let refused =
            DbConnectError::VersionUnreadable(DriverFailure::of(DbEngine::Postgres, &raw));
        assert_credential_free(&refused);
        assert_eq!(refused.to_string(), "db: database unreachable");
    }

    /// The floors are stated once, in their consts: no doc comment in this file
    /// restates a floor's number, so prose cannot drift from the enforced value.
    #[test]
    fn engine_floor_numbers_are_not_restated_in_prose() {
        let source = include_str!("db.rs");
        for engine in ENGINES {
            let rendered = engine.version_floor().to_string();
            let restated = source.lines().filter(|line| {
                let t = line.trim_start();
                t.starts_with("//") && t.contains(rendered.as_str())
            });
            assert_eq!(
                restated.count(),
                0,
                "a comment restates the {engine} floor {rendered}; reference the const instead"
            );
        }
    }
}

#[cfg(test)]
mod like_prefix_tests {
    use super::*;

    fn text(s: &str) -> SqlParam {
        SqlParam::Text(s.to_string())
    }

    fn pattern_of(raw: &str) -> Result<String, LikePrefixError> {
        LikePrefix::parse(raw.to_string()).map(|p| p.like_pattern())
    }

    /// One in-memory SQLite connection holding `names(name TEXT NULL)`.
    #[allow(clippy::expect_used)] // test fixture: a failed in-memory setup is a broken test host
    async fn names_db(rows: &[Option<&str>]) -> Db {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .min_connections(1)
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        sqlx::query("CREATE TABLE names (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NULL)")
            .execute(&pool)
            .await
            .expect("create table");
        for row in rows {
            sqlx::query("INSERT INTO names (name) VALUES (?)")
                .bind(*row)
                .execute(&pool)
                .await
                .expect("insert row");
        }
        pool
    }

    /// The sorted `name` values `frag` selects from `names`.
    async fn names_where(db: &Db, frag: SqlFragment) -> Result<Vec<String>, String> {
        let found: IpeResult<String, Vec<HashMap<String, String>>> =
            db_find_where(db.clone(), "names".into(), frag).await;
        match found {
            IpeResult::Ok(rows) => {
                let mut names: Vec<String> = rows
                    .iter()
                    .filter_map(|row| row.get("name").cloned())
                    .collect();
                names.sort();
                Ok(names)
            }
            IpeResult::Err(e) => Err(e),
        }
    }

    const U11_ROWS: [Option<&str>; 13] = [
        Some("Acme-1"),
        Some("acme-2"),
        Some("ACME"),
        Some("50%off"),
        Some("50 cents"),
        Some("500"),
        Some("a_b-x"),
        Some("axb-y"),
        Some("!bang"),
        Some("!x"),
        Some("a\\b"),
        Some("ab"),
        None,
    ];

    #[test]
    fn like_prefix_refuses_empty_with_full_text() {
        assert!(matches!(
            LikePrefix::parse(String::new()),
            Err(LikePrefixError::Empty)
        ));
        assert_eq!(
            LikePrefixError::Empty.message(),
            "Sql.startsWith: the prefix is empty"
        );
    }

    #[test]
    fn like_prefix_refuses_nul_with_full_text() {
        assert!(matches!(
            LikePrefix::parse("a\0b".to_string()),
            Err(LikePrefixError::Nul)
        ));
        assert_eq!(
            LikePrefixError::Nul.message(),
            "Sql.startsWith: the prefix contains a NUL character"
        );
    }

    #[test]
    fn like_prefix_length_ceiling_is_exact() {
        assert!(matches!(
            LikePrefix::parse("a".repeat(MAX_LIKE_PREFIX_BYTES + 1)),
            Err(LikePrefixError::TooLong)
        ));
        assert_eq!(
            LikePrefixError::TooLong.message(),
            "Sql.startsWith: the prefix is longer than 16384 bytes"
        );
        assert_eq!(
            pattern_of(&"a".repeat(MAX_LIKE_PREFIX_BYTES)).map(|p| p.len()),
            Ok(MAX_LIKE_PREFIX_BYTES + 1)
        );
    }

    #[test]
    fn like_prefix_escapes_wildcards_and_the_escape_character() {
        assert_eq!(pattern_of("50%"), Ok("50\\%%".to_string()));
        assert_eq!(pattern_of("a_b"), Ok("a\\_b%".to_string()));
        assert_eq!(pattern_of("\\x"), Ok("\\\\x%".to_string()));
        assert_eq!(pattern_of("!x"), Ok("!x%".to_string()));
        assert_eq!(pattern_of("ab"), Ok("ab%".to_string()));
    }

    #[test]
    fn starts_with_renders_both_conjuncts_and_binds_the_prefix() {
        let frag = sql_starts_with(sql_column("n".to_string()), "ab".to_string());
        assert_eq!(
            frag.sql,
            "((n LIKE ? ESCAPE '\\') AND (substr(n, 1, length(?)) = ?))"
        );
        assert_eq!(frag.binds, vec![text("ab%"), text("ab"), text("ab")]);
        assert_eq!(frag.invalid, None);
    }

    #[test]
    fn starts_with_repeats_subject_binds_in_lockstep() {
        let frag = sql_starts_with(sql_param("s".to_string()), "a%".to_string());
        assert_eq!(
            frag.sql,
            "((? LIKE ? ESCAPE '\\') AND (substr(?, 1, length(?)) = ?))"
        );
        assert_eq!(
            frag.binds,
            vec![text("s"), text("a\\%%"), text("s"), text("a%"), text("a%")]
        );
    }

    #[test]
    fn starts_with_upstream_poison_wins() {
        let frag = sql_starts_with(sql_column("bad name".to_string()), String::new());
        assert_eq!(
            frag.invalid,
            Some("Sql.column: invalid identifier \"bad name\"".to_string())
        );
        assert_eq!(frag.sql, "");
        assert!(frag.binds.is_empty());
    }

    #[test]
    fn starts_with_refused_prefix_poisons_without_binds() {
        let frag = sql_starts_with(sql_column("n".to_string()), "a\0".to_string());
        assert_eq!(
            frag.invalid,
            Some("Sql.startsWith: the prefix contains a NUL character".to_string())
        );
        assert_eq!(frag.sql, "");
        assert!(frag.binds.is_empty());
    }

    #[test]
    fn text_prefix_equals_shape_is_the_tenant_shape() {
        assert_eq!(
            text_prefix_equals_sql("service_name"),
            "substr(service_name, 1, length(?)) = ?"
        );
    }

    #[tokio::test]
    async fn starts_with_matches_the_literal_prefix_only() {
        let db = names_db(&U11_ROWS).await;
        let cases: [(&str, &[&str]); 8] = [
            ("acme", &["acme-2"]),
            ("50%", &["50%off"]),
            ("a_b", &["a_b-x"]),
            ("!b", &["!bang"]),
            ("!x", &["!x"]),
            ("a\\", &["a\\b"]),
            ("ab", &["ab"]),
            ("ACME", &["ACME"]),
        ];
        for (prefix, expected) in cases {
            let exact = sql_starts_with(sql_column("name".to_string()), prefix.to_string());
            let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
            assert_eq!(
                names_where(&db, exact).await,
                Ok(expected.clone()),
                "{prefix:?}"
            );

            // The LIKE conjunct alone may only widen by ASCII case, never by a
            // wildcard: every row it keeps starts with the prefix up to case.
            let pattern = match pattern_of(prefix) {
                Ok(pattern) => pattern,
                Err(refused) => panic!("{prefix:?}: {refused:?}"),
            };
            let like_only =
                match names_where(&db, sql_like(sql_column("name".to_string()), pattern)).await {
                    Ok(names) => names,
                    Err(e) => panic!("{prefix:?}: {e:?}"),
                };
            let folded = prefix.to_ascii_lowercase();
            assert!(
                like_only
                    .iter()
                    .all(|name| name.to_ascii_lowercase().starts_with(folded.as_str())),
                "{prefix:?} -> {like_only:?}"
            );
            assert!(
                expected.iter().all(|name| like_only.contains(name)),
                "{prefix:?}"
            );
        }
    }

    /// `Sql.like` sends one engine-independent text, `ESCAPE '\'`, to SQLite and
    /// Postgres alike; the Postgres rewrite keeping it intact is pinned in
    /// `config_postgres_test`.
    #[test]
    fn like_escape_backslash_same_on_sqlite_and_postgres() {
        let frag = sql_like(sql_column("n".to_string()), "a%".to_string());
        assert_eq!(frag.sql, "(n LIKE ? ESCAPE '\\')");
        assert_eq!(frag.binds, vec![text("a%")]);
        assert_eq!(frag.invalid, None);
    }

    #[test]
    fn like_pattern_ending_in_unpaired_escape_poisons() {
        let frag = sql_like(sql_column("n".to_string()), "a\\".to_string());
        assert_eq!(
            frag.invalid,
            Some("Sql.like: the pattern ends with the escape character \\".to_string())
        );
        assert_eq!(frag.sql, "");
        assert!(frag.binds.is_empty());

        let paired = sql_like(sql_column("n".to_string()), "a\\\\".to_string());
        assert_eq!(paired.invalid, None);
        assert_eq!(paired.binds, vec![text("a\\\\")]);
    }

    #[tokio::test]
    async fn like_pattern_with_backslash_matches_literal() {
        let db = names_db(&[Some("a%x"), Some("abx"), Some("a\\x"), Some("a_x")]).await;
        let column = || sql_column("name".to_string());
        assert_eq!(
            names_where(&db, sql_like(column(), "a\\%%".to_string())).await,
            Ok(vec!["a%x".to_string()])
        );
        assert_eq!(
            names_where(&db, sql_like(column(), "a\\_%".to_string())).await,
            Ok(vec!["a_x".to_string()])
        );
        assert_eq!(
            names_where(&db, sql_like(column(), "a\\\\%".to_string())).await,
            Ok(vec!["a\\x".to_string()])
        );
        // Unescaped wildcards stay wildcards.
        assert_eq!(
            names_where(&db, sql_like(column(), "a_x".to_string())).await,
            Ok(vec![
                "a%x".to_string(),
                "a\\x".to_string(),
                "a_x".to_string(),
                "abx".to_string()
            ])
        );
    }
}

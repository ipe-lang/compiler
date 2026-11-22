// Config stub for standalone crate testing.
// In generated projects this file is OVERRIDDEN by the Ipê compiler.
// `IpeError` is the real ADT from `error.rs`, re-exported at the crate root
// via `pub use error::*` — no `String` alias needed.

// Fail-closed driver guard: `db-sqlite` and `db-postgres` are mutually
// exclusive sqlx driver selectors. Only the emitter ever enables one (each
// generated project picks exactly one driver); this is a compile-time guard
// against a hand-written union, not a user surface.
#[cfg(all(feature = "db-sqlite", feature = "db-postgres"))]
compile_error!(
    "db-sqlite and db-postgres are mutually exclusive: a project selects exactly one sqlx driver"
);

#[cfg(feature = "db")]
pub type DbPool = sqlx::sqlite::SqlitePool;
#[cfg(feature = "db")]
pub type DbRow = sqlx::sqlite::SqliteRow;

#[cfg(not(feature = "db"))]
pub type DbPool = ();
#[cfg(not(feature = "db"))]
pub type DbRow = ();

// Backend-portability helpers. In generated projects these are
// REPLACED by Project.hs's per-driver impls (sqlite/mysql/postgres). The
// standalone runtime crate (used by `cargo test`) defaults to sqlite shapes.
#[cfg(feature = "db")]
pub fn db_last_insert_id(res: &sqlx::sqlite::SqliteQueryResult) -> i64 {
    res.last_insert_rowid()
}
#[cfg(feature = "db")]
pub fn db_format_sql(sql: String) -> String {
    sql
} // sqlite uses `?` placeholders

// Whether INSERT must use `… RETURNING id` to recover the auto-id (Postgres has
// no LastInsertId). Generated projects override per driver; standalone = sqlite.
#[cfg(feature = "db")]
pub const DB_USES_RETURNING_ID: bool = false;

// DDL fragment for an auto-incrementing primary key column. In
// generated projects the per-driver impl is emitted; standalone crate
// defaults to sqlite.
#[cfg(feature = "db")]
pub fn db_auto_id_column() -> &'static str {
    "id INTEGER PRIMARY KEY AUTOINCREMENT"
}

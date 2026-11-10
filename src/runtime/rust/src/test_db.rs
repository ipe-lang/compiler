//! The SQLite pools the runtime's own tests open.
//!
//! `crate::db::Db` is the pool of whichever engine `config` selects, so a test
//! may build one only where that engine is SQLite. Every test pool is built
//! here, and `mod.rs` compiles this module exactly when `config` is the SQLite
//! set: a SQLite fixture fed to a PostgreSQL `Db` has no representation.
#![cfg(test)]

use crate::db::Db;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

/// A one-connection in-memory database.
///
/// Every `sqlite::memory:` connection is its own database, so one connection
/// keeps a test's tables, transactions and rows visible to all its queries.
#[allow(clippy::expect_used)] // test fixture: a failed in-memory open is a broken test host
pub async fn memory() -> Db {
    SqlitePoolOptions::new()
        .min_connections(1)
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite")
}

/// A pool of at most `max_connections` over `options`, with no checkout hook.
#[allow(clippy::expect_used)] // test fixture: a failed open is a broken test host
pub async fn with_options(options: SqliteConnectOptions, max_connections: u32) -> Db {
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await
        .expect("connect sqlite")
}

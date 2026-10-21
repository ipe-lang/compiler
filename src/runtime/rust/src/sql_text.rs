//! The one site that vouches for SQL text sqlx cannot see is a literal.
//!
//! sqlx accepts a `&'static str` as query text directly; any other string must be
//! wrapped in `sqlx::AssertSqlSafe`, the driver's assertion that the text carries
//! no injected input. The runtime constructs that wrapper here and nowhere else
//! (`tests/sql_safe_single_site.rs` refuses a second site). Each entry point names
//! where its text comes from, so every dynamic query is one audited call away
//! from the provenance it relies on.

/// Vouch for SQL text the runtime assembled at run time.
///
/// The text must be built only from compiler-emitted SQL literals, identifiers the
/// runtime validated (`SqlIdent`, `SqlFragment`, `TenantPrefix`) and placeholders;
/// every value reaches the driver as a bound parameter, never spliced into the
/// text.
pub(crate) fn assembled(sql: String) -> impl sqlx::SqlSafeStr {
    vouch(sql)
}

/// Vouch for SQL text the Ipê program wrote and handed to a `Db` kernel.
///
/// The program owns this text (`Db.exec` and the `Ipe.Db.Unsafe` members, whose
/// import discloses the `unsafe` capability); the runtime only rewrites its
/// placeholders for the backend. Values the surface accepts as binds reach the
/// driver as bound parameters.
pub(crate) fn program_authored(sql: String) -> impl sqlx::SqlSafeStr {
    vouch(sql)
}

fn vouch(sql: String) -> impl sqlx::SqlSafeStr {
    sqlx::AssertSqlSafe(sql)
}

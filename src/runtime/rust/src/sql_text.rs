//! The one site that vouches for run-time-assembled SQL text.
//!
//! sqlx accepts a `&'static str` as query text directly; any other string must be
//! wrapped in `sqlx::AssertSqlSafe`, which is the driver's trust assertion that
//! the text carries no injected input. The runtime makes that assertion here and
//! nowhere else (`tests/sql_safe_single_site.rs` refuses a second site), so every
//! dynamic query is one audited call away from its invariant.

/// Vouch for SQL text the runtime assembled at run time.
///
/// The text must be built only from compiler-emitted SQL literals, identifiers the
/// runtime validated (`SqlFragment`, `TenantPrefix`, quoted column and table
/// names) and placeholders; every value reaches the driver as a bound parameter,
/// never spliced into the text.
pub(crate) fn assembled(sql: String) -> sqlx::AssertSqlSafe<String> {
    sqlx::AssertSqlSafe(sql)
}

// Postgres driver aliases.
//
// The crate root compiles this file as `config` when the `db-postgres` feature
// is on (a dependency-model project whose `package.ipe` database driver is
// `Postgres`); every other build compiles `config.rs`, the sqlite variant. The
// vendored model writes it verbatim to `<emitted-project>/src/ipe_runtime/config.rs`
// through `ipe_backend_rust::project`'s `RUNTIME_CONFIG_RS_DB_POSTGRES`.
//
// Every symbol name matches `config.rs`'s sqlite variant exactly (`DbPool`,
// `DbRow`, `ipe_db_url`, `db_last_insert_id`, `db_format_sql`,
// `DB_USES_RETURNING_ID`, `db_auto_id_column`) so `db.rs` — copied verbatim
// across both driver builds — never needs a driver-specific `#[cfg]`.

#[cfg(feature = "db")]
pub type DbPool = sqlx::postgres::PgPool;
#[cfg(feature = "db")]
pub type DbRow = sqlx::postgres::PgRow;
#[cfg(feature = "db")]
pub fn ipe_db_url() -> String {
    // One config precedence `env > setting-in-code > fallback`: `DATABASE_URL`
    // wins, else an installed `Db.url` setting (a `Secret`, revealed only here at
    // the point of use, never logged), else the built-in local fallback.
    crate::system::read_env_var("DATABASE_URL")
        .ok()
        .or_else(crate::app_config::resolve_db_url_override)
        .unwrap_or_else(|| "postgres://postgres@localhost/ipe".to_string())
}

#[cfg(not(feature = "db"))]
pub type DbPool = ();
#[cfg(not(feature = "db"))]
pub type DbRow = ();
#[cfg(not(feature = "db"))]
pub fn ipe_db_url() -> String {
    String::new()
}

// Backend-portability helpers. Mirrors `config.rs`'s sqlite shape.
#[cfg(feature = "db")]
pub fn db_last_insert_id(_res: &sqlx::postgres::PgQueryResult) -> i64 {
    // Postgres's `QueryResult` carries no last-insert-id concept.
    // `DB_USES_RETURNING_ID = true` routes every `db_insert_row` call through
    // the `RETURNING id` branch instead, so this fn is never called on the
    // success path for `db_insert_row`. It IS still reachable from
    // `db_insert_fields` / `db_update_fields` on the non-`RETURNING` path — but
    // `db_insert_fields` (`db.rs`) gates its own call to this fn behind
    // `DB_USES_RETURNING_ID`, exactly like `db_insert_row`, so it is unreached
    // there too. Returning 0 unconditionally would be a fabricated value if it
    // WERE ever reached; kept as a documented "should be unreachable" stub
    // rather than a panic, matching the pre-existing sqlite behaviour for a
    // table with no autoincrement column (never a new regression surface).
    0
}

#[cfg(feature = "db")]
pub fn db_format_sql(sql: String) -> String {
    // Postgres's extended query protocol uses numbered placeholders ($1, $2,
    // …), not sqlite's positional `?`. Every SQL string built throughout
    // `db.rs` is written with `?` placeholders in emission order, matching the
    // order args are bound, so a sequential rewrite (first `?` → $1, second →
    // $2, …) maps placeholders to args backend-independently.
    //
    // The rewrite is quote-aware: `Db.exec`/`Db.unsafeQuery`/`Db.queryDecode`
    // route app-authored SQL text through here, and that text may contain a
    // literal `?` inside a quoted string, a quoted identifier, or a comment
    // (`SELECT * FROM t WHERE note = 'why?'`). Only a `?` in ordinary SQL text
    // is a placeholder; a `?` inside a span below is copied verbatim so the
    // literal and every later placeholder's numbering stay intact.
    //
    // Skipped spans (Postgres lexical rules):
    //   - single-quoted string literal `'…'`, `''` an embedded quote
    //   - double-quoted identifier `"…"`, `""` an embedded quote
    //   - dollar-quoted string `$tag$…$tag$` (tag may be empty: `$$…$$`)
    //   - line comment `-- …` to end of line
    //   - block comment `/* … */` (Postgres nests these)
    //
    // Every span length is measured from ASCII delimiters, which never occur
    // inside a multi-byte UTF-8 sequence, so each split lands on a char
    // boundary.
    let mut out = String::with_capacity(sql.len().saturating_add(8));
    let mut placeholder: usize = 0;
    let mut rest: &str = &sql;
    while let Some(head) = rest.chars().next() {
        let tail = rest.get(head.len_utf8()..).unwrap_or_default();
        let span_len = match head {
            '?' => {
                placeholder = placeholder.saturating_add(1);
                out.push('$');
                out.push_str(&placeholder.to_string());
                rest = tail;
                continue;
            }
            '\'' => Some(quoted_len(rest.as_bytes(), b'\'')),
            '"' => Some(quoted_len(rest.as_bytes(), b'"')),
            '$' => dollar_quoted_len(rest.as_bytes()),
            '-' if tail.starts_with('-') => Some(
                rest.find('\n')
                    .map_or(rest.len(), |nl| nl.saturating_add(1)),
            ),
            '/' if tail.starts_with('*') => Some(block_comment_len(rest.as_bytes())),
            _ => None,
        };
        match span_len.and_then(|len| rest.get(..len).zip(rest.get(len..))) {
            Some((span, after)) => {
                out.push_str(span);
                rest = after;
            }
            None => {
                out.push(head);
                rest = tail;
            }
        }
    }
    out
}

// Byte length of the quoted span opening at `bytes[0]` (`quote`), closer
// included; a doubled quote is an escaped quote inside the span. An
// unterminated span runs to the end.
#[cfg(feature = "db")]
fn quoted_len(bytes: &[u8], quote: u8) -> usize {
    let mut j = 1usize;
    while let Some(&c) = bytes.get(j) {
        if c == quote {
            if bytes.get(j.saturating_add(1)) == Some(&quote) {
                j = j.saturating_add(2);
                continue;
            }
            return j.saturating_add(1);
        }
        j = j.saturating_add(1);
    }
    bytes.len()
}

// Byte length of the dollar-quoted string opening at `bytes[0] == b'$'`, both
// `$tag$` delimiters included, or `None` when `bytes` does not open a
// dollar-quote tag (zero or more letters/digits/underscores, not starting with
// a digit). An unterminated body runs to the end (sqlx surfaces the malformed
// SQL as an error).
#[cfg(feature = "db")]
fn dollar_quoted_len(bytes: &[u8]) -> Option<usize> {
    let mut j = 1usize;
    let tag_end = loop {
        let c = *bytes.get(j)?;
        if c == b'$' {
            break j.saturating_add(1);
        }
        let ok = c == b'_' || c.is_ascii_alphabetic() || (j > 1 && c.is_ascii_digit());
        if !ok {
            return None;
        }
        j = j.saturating_add(1);
    };
    let tag = bytes.get(..tag_end)?;
    let body = bytes.get(tag_end..).unwrap_or_default();
    Some(
        body.windows(tag.len())
            .position(|w| w == tag)
            .map_or(bytes.len(), |p| {
                tag_end.saturating_add(p).saturating_add(tag.len())
            }),
    )
}

// Byte length of the block comment opening at `bytes[..2] == b"/*"`, closer
// included. Postgres nests block comments, so track depth; an unterminated
// comment runs to the end.
#[cfg(feature = "db")]
fn block_comment_len(bytes: &[u8]) -> usize {
    let mut j = 2usize;
    let mut depth = 1usize;
    loop {
        match (bytes.get(j), bytes.get(j.saturating_add(1))) {
            (Some(b'/'), Some(b'*')) => {
                depth = depth.saturating_add(1);
                j = j.saturating_add(2);
            }
            (Some(b'*'), Some(b'/')) => {
                depth = depth.saturating_sub(1);
                j = j.saturating_add(2);
                if depth == 0 {
                    return j;
                }
            }
            (Some(_), Some(_)) => j = j.saturating_add(1),
            _ => return bytes.len(),
        }
    }
}

// Whether INSERT must use `… RETURNING id` to recover the auto-id (Postgres
// has no LastInsertId).
#[cfg(feature = "db")]
pub const DB_USES_RETURNING_ID: bool = true;

// DDL fragment for an auto-incrementing primary key column.
#[cfg(feature = "db")]
pub fn db_auto_id_column() -> &'static str {
    "id BIGSERIAL PRIMARY KEY"
}

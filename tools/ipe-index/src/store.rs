use crate::diff::{Change, QueueOp, Snapshot, UnitState};
use crate::model::{Kind, Unit};
use crate::repo_set::{MAX_REPOS, RecordedRoot};
use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension};

pub struct Store {
    pub conn: Connection,
}

/// The index tables: `units`/`links`/`callgraph`/`change_queue` are the review
/// backbone; `repos` is the root set the index was built under (a root nested
/// in another records that root's tag and its prefix there, both or neither).
///
/// All `CREATE … IF NOT EXISTS` so an old DB gains missing tables on
/// open; `index` drops and recreates every table except `change_queue`,
/// `reviewed` and `reviewed_stamp`. `change_queue` rows only the queue
/// reconciliation (`diff::reconcile`) and the review app's drain ever change.
/// `reviewed` is the review app's copy of its decided `(uid, body_hash)`
/// pairs, and `reviewed_stamp` names the review-database state that copy
/// reflects: the review app is the sole writer of both, and ipe-index never
/// touches their rows. The CHECK constraints make an invalid enum literal
/// unrepresentable at the DB layer (the extractor is the only writer and only
/// emits the allowed values). [`OPEN_UNITS_VIEW`] follows the tables in the
/// schema fixture `tests/schema.sql`.
const TABLE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS files   (path TEXT PRIMARY KEY, lang TEXT, role TEXT, size INTEGER, sha TEXT);
CREATE TABLE IF NOT EXISTS symbols (file TEXT, name TEXT, kind TEXT, line INTEGER, col INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS edges   (src TEXT, dst TEXT, kind TEXT, resolved TEXT);
CREATE TABLE IF NOT EXISTS meta    (k TEXT PRIMARY KEY, v TEXT);
CREATE INDEX IF NOT EXISTS i_sym_name ON symbols(name);
CREATE INDEX IF NOT EXISTS i_edge_src ON edges(src);
CREATE INDEX IF NOT EXISTS i_edge_dst ON edges(dst);
CREATE UNIQUE INDEX IF NOT EXISTS u_edge ON edges(src, dst, kind);
CREATE TABLE IF NOT EXISTS units (
  uid         TEXT PRIMARY KEY,
  path        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('module','file','fn','struct','enum','impl','const','binding','block','trait')),
  name        TEXT NOT NULL,
  qualified   TEXT NOT NULL,
  line_start  INTEGER NOT NULL,
  line_end    INTEGER NOT NULL,
  facing      TEXT NOT NULL CHECK (facing IN ('user','internal','test')),
  purpose     TEXT,
  body_hash   TEXT NOT NULL,
  updated_sha TEXT NOT NULL,
  residual_hash TEXT
);
CREATE INDEX IF NOT EXISTS i_units_path ON units(path);
CREATE INDEX IF NOT EXISTS i_units_name ON units(name);
CREATE INDEX IF NOT EXISTS i_units_qual ON units(qualified);
CREATE TABLE IF NOT EXISTS links (
  from_uid TEXT NOT NULL,
  to_kind  TEXT NOT NULL CHECK (to_kind IN ('internal','external')),
  to_uid   TEXT,
  to_ref   TEXT NOT NULL,
  line     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS i_links_from ON links(from_uid);
CREATE INDEX IF NOT EXISTS i_links_to   ON links(to_uid);
CREATE UNIQUE INDEX IF NOT EXISTS u_links ON links(from_uid,to_kind,to_uid,to_ref,line);
CREATE TABLE IF NOT EXISTS callgraph (
  caller_uid TEXT NOT NULL,
  callee_uid TEXT NOT NULL,
  UNIQUE(caller_uid, callee_uid)
);
CREATE INDEX IF NOT EXISTS i_cg_caller ON callgraph(caller_uid);
CREATE INDEX IF NOT EXISTS i_cg_callee ON callgraph(callee_uid);
CREATE TABLE IF NOT EXISTS change_queue (
  uid          TEXT PRIMARY KEY,
  change       TEXT NOT NULL CHECK (change IN ('new','modified','deleted')),
  old_hash     TEXT,
  new_hash     TEXT,
  enqueued_sha TEXT NOT NULL,
  enqueued_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reviewed (
  uid       TEXT NOT NULL,
  body_hash TEXT NOT NULL,
  PRIMARY KEY (uid, body_hash)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS repos (
  tag    TEXT PRIMARY KEY,
  outer  TEXT,
  prefix TEXT,
  CHECK ((outer IS NULL) = (prefix IS NULL))
);
CREATE TABLE IF NOT EXISTS reviewed_stamp (
  one  INTEGER PRIMARY KEY CHECK (one = 1),
  head TEXT NOT NULL CHECK (typeof(head) = 'text' AND head <> '')
);
";

/// Drops the view so [`OPEN_UNITS_VIEW`] can be created in its place.
const OPEN_UNITS_VIEW_RESET: &str = "DROP VIEW IF EXISTS open_units;\n";

/// The open backlog: every current unit whose `(uid, body_hash)` is not decided.
///
/// Membership ranges over `units` and subtracts `reviewed`, so a unit that is
/// gone, or decided under other bytes, is judged by the tree as it is now. The
/// change queue only annotates a row (change kind, old hash, enqueue order):
/// it never decides whether a unit is listed, so a drained or missing queue
/// row cannot hide an undecided unit. A unit with no queue row for its current
/// hash has a NULL `change` and sorts first (`enqueued_at` 0).
const OPEN_UNITS_VIEW: &str = "CREATE VIEW open_units AS
  SELECT u.uid, u.path, u.kind, u.name, u.qualified, u.line_start, u.line_end,
         u.facing, u.purpose, u.body_hash, u.updated_sha, f.lang,
         q.change, q.old_hash, COALESCE(q.enqueued_at, 0) AS enqueued_at
  FROM units u
  LEFT JOIN files f ON f.path = u.path
  LEFT JOIN change_queue q
         ON q.uid = u.uid AND q.new_hash = u.body_hash
        AND q.change IN ('new', 'modified')
  WHERE NOT EXISTS (SELECT 1 FROM reviewed r
                    WHERE r.uid = u.uid AND r.body_hash = u.body_hash)";

/// Current schema version: v8 is v7 plus the `open_units` view and the
/// `reviewed_stamp` table; a v7 index has neither, so it is rebuilt before the
/// review app reads it. v7 is v6 plus the `repos` root set the rows were
/// indexed under; a v6 index records none, so its owner of each path is
/// unknown. v6 rows are the v5 format, extracted only from
/// regular files named by their exact bytes; v5 rows may hold the units of a
/// tracked symbolic link's target, a submodule path, or a lossily decoded name,
/// which an incremental `update` would keep for every unchanged path. v5 `file`
/// units attest their residual (the lines no other unit of the file covers) in
/// `body_hash` and leave `residual_hash` NULL; v4 `file` units attest the whole file in `body_hash` and the residual
/// in `residual_hash`; v3 rows carry `sha256:` view attestations in
/// `body_hash` and no residual; v2 rows a bare blake3 of the span. `open`
/// stamps it only on a DB with no units yet, so a stamp always describes the
/// rows beside it; a DB holding rows of another version keeps its stamp until
/// `index` rebuilds it.
const SCHEMA_VERSION: &str = "8";

/// Stable unit id: blake3 of `path|kind|qualified`. Content-stable across
/// re-indexes; a rename of the symbol or path changes the id by design.
pub fn unit_uid(path: &str, kind: Kind, qualified: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(path.as_bytes());
    h.update(b"|");
    h.update(kind.as_str().as_bytes());
    h.update(b"|");
    h.update(qualified.as_bytes());
    h.finalize().to_hex().to_string()
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(TABLE_SCHEMA)?;
        ensure_open_units_view(&conn)?;
        ensure_schema_version(&conn)?;
        Ok(Store { conn })
    }
    pub fn begin(&self) -> Result<()> {
        // IMMEDIATE takes the write lock before the first read, so the
        // snapshot a run diffs is the state its writes land on: no drain by
        // the review app can commit between the two and be overwritten.
        self.conn.execute_batch("BEGIN IMMEDIATE;")?;
        Ok(())
    }
    pub fn rollback(&self) -> Result<()> {
        self.conn.execute_batch("ROLLBACK;")?;
        Ok(())
    }
    pub fn commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT;")?;
        Ok(())
    }
    pub fn put_file(&self, path: &str, lang: &str, role: &str, size: i64, sha: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO files VALUES (?,?,?,?,?)",
            rusqlite::params![path, lang, role, size, sha],
        )?;
        Ok(())
    }
    pub fn put_symbol(
        &self,
        file: &str,
        name: &str,
        kind: &str,
        line: i64,
        col: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO symbols VALUES (?,?,?,?,?)",
            rusqlite::params![file, name, kind, line, col],
        )?;
        Ok(())
    }
    pub fn put_edge(&self, src: &str, dst: &str, kind: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO edges(src,dst,kind) VALUES (?,?,?)",
            rusqlite::params![src, dst, kind],
        )?;
        Ok(())
    }
    pub fn put_unit(&self, u: &Unit) -> Result<()> {
        let uid = unit_uid(&u.path, u.kind, &u.qualified);
        self.conn.execute(
            "INSERT OR REPLACE INTO units (uid, path, kind, name, qualified, line_start, \
             line_end, facing, purpose, body_hash, updated_sha) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![
                uid,
                u.path,
                u.kind.as_str(),
                u.name,
                u.qualified,
                u.line_start,
                u.line_end,
                u.facing.as_str(),
                u.purpose,
                u.body_hash,
                u.updated_sha
            ],
        )?;
        Ok(())
    }
    pub fn put_link(
        &self,
        from_uid: &str,
        to_kind: &str,
        to_uid: Option<&str>,
        to_ref: &str,
        line: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO links(from_uid,to_kind,to_uid,to_ref,line) VALUES (?,?,?,?,?)",
            rusqlite::params![from_uid, to_kind, to_uid, to_ref, line],
        )?;
        Ok(())
    }
    pub fn put_call(&self, caller_uid: &str, callee_uid: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO callgraph(caller_uid,callee_uid) VALUES (?,?)",
            rusqlite::params![caller_uid, callee_uid],
        )?;
        Ok(())
    }
    /// The line spans of every non-`file` unit of `path`.
    pub fn child_spans(&self, path: &str) -> Result<Vec<(i64, i64)>> {
        let mut st = self
            .conn
            .prepare("SELECT line_start, line_end FROM units WHERE path=? AND kind != 'file'")?;
        let rows = st.query_map([path], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
    /// Applies one queue operation; the only writer of `change_queue`.
    ///
    /// `New`/`Modified`/`Deleted` replace the unit's row, so a unit holds at
    /// most one pending change. `Refresh` re-points an existing row at the
    /// current body hash and never creates one.
    pub fn apply(&self, op: &QueueOp, sha: &str, at: i64) -> Result<()> {
        let (change, old_hash, new_hash) = match &op.change {
            Change::New { new_hash } => ("new", None, Some(new_hash)),
            Change::Modified { old_hash, new_hash } => ("modified", Some(old_hash), Some(new_hash)),
            Change::Deleted { old_hash } => ("deleted", Some(old_hash), None),
            Change::Refresh { new_hash } => {
                self.conn.execute(
                    "UPDATE change_queue SET new_hash=? WHERE uid=?",
                    rusqlite::params![new_hash, op.uid],
                )?;
                return Ok(());
            }
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO change_queue VALUES (?,?,?,?,?,?)",
            rusqlite::params![op.uid, change, old_hash, new_hash, sha, at],
        )?;
        Ok(())
    }
    pub fn drop_file(&self, path: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM files WHERE path=?", [path])?;
        self.conn
            .execute("DELETE FROM symbols WHERE file=?", [path])?;
        self.conn.execute("DELETE FROM edges WHERE src=?", [path])?;
        // Units/links/callgraph are keyed by uid; delete everything owned by
        // this path's units (and links pointing at them).
        self.conn.execute(
            "DELETE FROM links WHERE from_uid IN (SELECT uid FROM units WHERE path=?) \
             OR to_uid IN (SELECT uid FROM units WHERE path=?)",
            rusqlite::params![path, path],
        )?;
        self.conn.execute(
            "DELETE FROM callgraph WHERE caller_uid IN (SELECT uid FROM units WHERE path=?) \
             OR callee_uid IN (SELECT uid FROM units WHERE path=?)",
            rusqlite::params![path, path],
        )?;
        self.conn
            .execute("DELETE FROM units WHERE path=?", [path])?;
        Ok(())
    }
    pub fn set_meta(&self, k: &str, v: &str) -> Result<()> {
        self.conn
            .execute("INSERT OR REPLACE INTO meta VALUES (?,?)", [k, v])?;
        Ok(())
    }
    pub fn get_meta(&self, k: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k=?", [k], |r| r.get(0))
            .ok())
    }
    /// Records the root set this index is built under, replacing any earlier one.
    pub fn record_repos(&self, roots: &[RecordedRoot]) -> Result<()> {
        self.conn.execute("DELETE FROM repos", [])?;
        for root in roots {
            let (outer, prefix) = match &root.nesting {
                Some((outer, prefix)) => (Some(outer.as_str()), Some(prefix.as_str())),
                None => (None, None),
            };
            self.conn.execute(
                "INSERT INTO repos (tag, outer, prefix) VALUES (?,?,?)",
                rusqlite::params![root.tag, outer, prefix],
            )?;
        }
        Ok(())
    }
    /// The root set this index was built under, sorted by tag.
    ///
    /// At most one row past [`MAX_REPOS`] is read: a longer set already
    /// differs from any set a run may declare.
    pub fn recorded_repos(&self) -> Result<Vec<RecordedRoot>> {
        let limit = i64::try_from(MAX_REPOS.saturating_add(1))?;
        let mut st = self
            .conn
            .prepare("SELECT tag, outer, prefix FROM repos ORDER BY tag LIMIT ?")?;
        let rows = st.query_map([limit], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut roots = Vec::new();
        for row in rows {
            let (tag, outer, prefix) = row?;
            let nesting = match (outer, prefix) {
                (None, None) => None,
                (Some(outer), Some(prefix)) => Some((outer, prefix)),
                (Some(_), None) | (None, Some(_)) => bail!(
                    "ipe-index: the recorded root `{}` has only half of its nesting",
                    crate::walk::shown(&tag)
                ),
            };
            roots.push(RecordedRoot { tag, nesting });
        }
        Ok(roots)
    }
    pub fn count(&self, table: &str) -> Result<i64> {
        // Defense-in-depth: map table names to static SQL literals instead of formatting.
        // This ensures no caller value (even allowlisted) is interpolated into the SQL string.
        let sql = match table {
            "files" => "SELECT COUNT(*) FROM files",
            "symbols" => "SELECT COUNT(*) FROM symbols",
            "edges" => "SELECT COUNT(*) FROM edges",
            "units" => "SELECT COUNT(*) FROM units",
            "links" => "SELECT COUNT(*) FROM links",
            "callgraph" => "SELECT COUNT(*) FROM callgraph",
            "change_queue" => "SELECT COUNT(*) FROM change_queue",
            _ => bail!("store::count: unexpected table name {table:?}"),
        };
        Ok(self.conn.query_row(sql, [], |r| r.get(0))?)
    }
    // Used only in unit tests (the CLI `locate` path runs its own SQL);
    // suppress the dead_code lint the non-test build would otherwise fire.
    #[allow(dead_code)]
    pub fn symbols_named(&self, name: &str) -> Result<Vec<(String, i64, i64)>> {
        let mut st = self
            .conn
            .prepare("SELECT file,line,col FROM symbols WHERE name=? ORDER BY file")?;
        let rows = st.query_map([name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
    /// The queue state of every unit of `path`.
    pub fn snapshot_path(&self, path: &str) -> Result<Snapshot> {
        self.snapshot(
            "SELECT uid, path, body_hash, COALESCE(residual_hash, body_hash) \
             FROM units WHERE path=?1",
            Some(path),
        )
    }
    /// The queue state of every unit in the index. A v4 file row is keyed by
    /// its `residual_hash`, which equals the `body_hash` a v5 row stores for
    /// the same residual. A `units` table of an older schema has no
    /// `residual_hash`; its file units are keyed by their whole body, so the
    /// first rebuild over it queues each changed file once.
    pub fn snapshot_all(&self) -> Result<Snapshot> {
        let has_residual: bool = self.conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('units') WHERE name='residual_hash'",
            [],
            |r| r.get(0),
        )?;
        let sql = if has_residual {
            "SELECT uid, path, body_hash, COALESCE(residual_hash, body_hash) FROM units"
        } else {
            "SELECT uid, path, body_hash, body_hash FROM units"
        };
        self.snapshot(sql, None)
    }
    fn snapshot(&self, sql: &str, path: Option<&str>) -> Result<Snapshot> {
        let mut st = self.conn.prepare(sql)?;
        let row = |r: &rusqlite::Row<'_>| {
            Ok((
                r.get::<_, String>(0)?,
                UnitState {
                    path: r.get(1)?,
                    body_hash: r.get(2)?,
                    change_key: r.get(3)?,
                },
            ))
        };
        let rows = match path {
            Some(p) => st
                .query_map([p], row)?
                .collect::<std::result::Result<_, _>>()?,
            None => st
                .query_map([], row)?
                .collect::<std::result::Result<_, _>>()?,
        };
        Ok(rows)
    }
    /// Empties the index for a full rebuild: every derived table is dropped
    /// and recreated in the current shape, `meta` is cleared and restamped
    /// current, `change_queue` is kept for the rebuild to reconcile, and
    /// `reviewed` with its `reviewed_stamp` are kept because only the review
    /// app writes them. The `open_units` view is a definition over the
    /// recreated tables, so it is kept too.
    pub fn reset_index(&self) -> Result<()> {
        self.conn.execute_batch(
            "DROP TABLE IF EXISTS files; DROP TABLE IF EXISTS symbols; \
             DROP TABLE IF EXISTS edges; DROP TABLE IF EXISTS units; \
             DROP TABLE IF EXISTS links; DROP TABLE IF EXISTS callgraph; \
             DROP TABLE IF EXISTS repos; DELETE FROM meta;",
        )?;
        self.conn.execute_batch(TABLE_SCHEMA)?;
        ensure_open_units_view(&self.conn)?;
        self.set_meta("schema_version", SCHEMA_VERSION)
    }
    /// Resolve a unit by exact qualified name (callee lookup). A Rust qualified
    /// name is rooted at its crate (`backend::run`, not `crate::run`), so the
    /// name alone pins one crate; the same-path preference then disambiguates
    /// two files that legitimately share a qualified name within that crate.
    /// `None` when no unit qualifies.
    pub fn uid_for_qualified(&self, qualified: &str, path: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT uid FROM units WHERE qualified=?1 \
             ORDER BY (path=?2) DESC, uid LIMIT 1",
                rusqlite::params![qualified, path],
                |r| r.get(0),
            )
            .ok())
    }
}

/// Makes the `open_units` view this binary's own definition.
///
/// A view holds no rows, so it is replaced whenever the stored text differs.
/// A current view is left alone: every query command opens the store, and a
/// rewrite there would take the write lock a running rebuild holds.
fn ensure_open_units_view(conn: &Connection) -> Result<()> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'open_units'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if stored.as_deref() == Some(OPEN_UNITS_VIEW) {
        return Ok(());
    }
    // One savepoint, so a reader never sees the view dropped but not created.
    conn.execute_batch(&format!(
        "SAVEPOINT open_units_view;\n{OPEN_UNITS_VIEW_RESET}{OPEN_UNITS_VIEW};\nRELEASE open_units_view;"
    ))?;
    Ok(())
}

/// Stamps `SCHEMA_VERSION` on a DB that holds no units and no version yet.
/// A DB already holding rows keeps whatever version it records (or none):
/// restamping would claim its stored hashes are in the current format.
fn ensure_schema_version(conn: &Connection) -> Result<()> {
    if read_schema_version(conn)?.is_none() {
        let units: i64 = conn.query_row("SELECT COUNT(*) FROM units", [], |r| r.get(0))?;
        if units == 0 {
            conn.execute(
                "INSERT INTO meta VALUES ('schema_version', ?)",
                [SCHEMA_VERSION],
            )?;
        }
    }
    Ok(())
}

fn read_schema_version(conn: &Connection) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT v FROM meta WHERE k='schema_version'", [], |r| {
            r.get(0)
        })
        .optional()?)
}

impl Store {
    /// True when the DB's rows are in the current format. An incremental
    /// `update` re-extracts only changed files, so it must not run over rows
    /// of another version: their stored hashes would never be re-made.
    pub fn schema_is_current(&self) -> Result<bool> {
        Ok(read_schema_version(&self.conn)?.as_deref() == Some(SCHEMA_VERSION))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Facing;
    #[test]
    fn roundtrip() {
        let s = Store::open(":memory:").unwrap();
        s.put_file("a.rs", "rs", "runtime-rs", 10, "deadbeef")
            .unwrap();
        s.put_symbol("a.rs", "list_head", "fn", 5, 0).unwrap();
        s.put_edge("a.rs", "b.rs", "import").unwrap();
        assert_eq!(s.count("files").unwrap(), 1);
        assert_eq!(s.count("symbols").unwrap(), 1);
        assert_eq!(s.count("edges").unwrap(), 1);
        let fns = s.symbols_named("list_head").unwrap();
        assert_eq!(fns, vec![("a.rs".to_string(), 5, 0)]);
    }

    #[test]
    fn test_symbol_col_captured() {
        let s = Store::open(":memory:").unwrap();
        s.put_symbol("b.rs", "my_fn", "def", 10, 5).unwrap();
        let hits = s.symbols_named("my_fn").unwrap();
        assert_eq!(hits, vec![("b.rs".to_string(), 10, 5)]);
    }

    #[test]
    fn test_edge_dedup() {
        let s = Store::open(":memory:").unwrap();
        s.put_edge("a.rs", "b.rs", "import").unwrap();
        s.put_edge("a.rs", "b.rs", "import").unwrap(); // duplicate — should be ignored
        assert_eq!(s.count("edges").unwrap(), 1);
    }

    fn sample_unit(path: &str, name: &str, qualified: &str) -> Unit {
        Unit {
            path: path.to_string(),
            kind: Kind::Fn,
            name: name.to_string(),
            qualified: qualified.to_string(),
            line_start: 1,
            line_end: 5,
            facing: Facing::Internal,
            purpose: Some("does the thing".to_string()),
            body_hash: "sha256:00".to_string(),
            updated_sha: "cafe".to_string(),
        }
    }

    #[test]
    fn unit_roundtrip_dedups_by_uid() {
        let s = Store::open(":memory:").unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap(); // same uid — replace
        assert_eq!(s.count("units").unwrap(), 1);
        // A different qualified name is a different unit.
        s.put_unit(&sample_unit("src/a.rs", "bar", "crate::bar"))
            .unwrap();
        assert_eq!(s.count("units").unwrap(), 2);
    }

    // `tools/code-review`'s tests seed a fake index DB from this exact file
    // (never a hand copy), so a drift here is caught by the Rust build
    // before the Ipê tests can certify a schema the real index never
    // creates.
    #[test]
    fn schema_fixture_matches_the_real_schema() {
        const FIXTURE: &str = include_str!("../tests/schema.sql");
        let schema = format!("{TABLE_SCHEMA}{OPEN_UNITS_VIEW_RESET}{OPEN_UNITS_VIEW};\n");
        assert_eq!(
            schema, FIXTURE,
            "tools/ipe-index/tests/schema.sql has drifted from the tables and the \
             `open_units` view in store.rs — update the fixture to match \
             (tools/code-review reads it verbatim)"
        );
    }

    // `tools/code-review` splits the fixture on `;`, so no statement may hold
    // one inside a literal or a comment.
    #[test]
    fn schema_statements_hold_no_inner_semicolon() {
        let script = format!("{TABLE_SCHEMA}{OPEN_UNITS_VIEW_RESET}{OPEN_UNITS_VIEW}");
        assert_eq!(
            script.matches(';').count(),
            script.matches(";\n").count(),
            "a `;` that does not end a line splits a statement in the fixture reader"
        );
        assert!(!OPEN_UNITS_VIEW.contains(';'));
    }

    #[test]
    fn schema_version_is_gated() {
        let s = Store::open(":memory:").unwrap();
        assert_eq!(
            s.get_meta("schema_version").unwrap().as_deref(),
            Some(SCHEMA_VERSION)
        );
        assert!(s.schema_is_current().unwrap());
    }

    // A DB recording an older version is never restamped on open: its rows
    // still carry the old hash format.
    #[test]
    fn older_schema_is_not_restamped() {
        let s = Store::open(":memory:").unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap();
        s.set_meta("schema_version", "2").unwrap();
        ensure_schema_version(&s.conn).unwrap();
        assert_eq!(s.get_meta("schema_version").unwrap().as_deref(), Some("2"));
        assert!(!s.schema_is_current().unwrap());
    }

    // A DB stamped with the previous version is not current, so `update`
    // refuses to run incrementally over it, and the full rebuild stamps it
    // current.
    #[test]
    fn an_older_schema_stamp_forces_a_full_rebuild_at_version_8() {
        assert_eq!(SCHEMA_VERSION, "8");
        let s = Store::open(":memory:").unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap();
        s.set_meta("schema_version", "7").unwrap();
        ensure_schema_version(&s.conn).unwrap();
        assert!(!s.schema_is_current().unwrap());
        s.reset_index().unwrap();
        assert_eq!(s.get_meta("schema_version").unwrap().as_deref(), Some("8"));
        assert!(s.schema_is_current().unwrap());
    }

    // A DB with units but no recorded version is not stamped current either.
    #[test]
    fn unversioned_rows_are_not_stamped() {
        let s = Store::open(":memory:").unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap();
        s.conn
            .execute("DELETE FROM meta WHERE k='schema_version'", [])
            .unwrap();
        ensure_schema_version(&s.conn).unwrap();
        assert_eq!(s.get_meta("schema_version").unwrap(), None);
        assert!(!s.schema_is_current().unwrap());
    }

    #[test]
    fn units_kind_check_rejects_invalid() {
        let s = Store::open(":memory:").unwrap();
        let err = s
            .conn
            .execute(
                "INSERT INTO units (uid, path, kind, name, qualified, line_start, line_end, \
                 facing, purpose, body_hash, updated_sha) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                rusqlite::params![
                    "uid",
                    "p",
                    "bogus",
                    "n",
                    "q",
                    1,
                    2,
                    "internal",
                    None::<String>,
                    "h",
                    "sha"
                ],
            )
            .unwrap_err();
        assert!(err.to_string().contains("CHECK"), "got: {err}");
    }

    #[test]
    fn drop_file_removes_owned_rows() {
        let s = Store::open(":memory:").unwrap();
        s.put_file("src/a.rs", "rs", "compiler-rs", 10, "").unwrap();
        s.put_unit(&sample_unit("src/a.rs", "foo", "crate::foo"))
            .unwrap();
        let uid = unit_uid("src/a.rs", Kind::Fn, "crate::foo");
        s.put_link(&uid, "internal", Some(&uid), "crate::foo", 3)
            .unwrap();
        s.put_call(&uid, &uid).unwrap();
        assert_eq!(s.count("units").unwrap(), 1);
        assert_eq!(s.count("links").unwrap(), 1);
        assert_eq!(s.count("callgraph").unwrap(), 1);
        s.drop_file("src/a.rs").unwrap();
        assert_eq!(s.count("files").unwrap(), 0);
        assert_eq!(s.count("units").unwrap(), 0);
        assert_eq!(s.count("links").unwrap(), 0);
        assert_eq!(s.count("callgraph").unwrap(), 0);
    }

    fn reviewed_rows(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM reviewed", [], |r| r.get(0))
            .unwrap()
    }

    // An index created before the `reviewed` table existed gains it on open.
    // The shared in-memory DB lives while `older` holds it open.
    #[test]
    fn reviewed_table_created_on_open() {
        let uri = "file:reviewed_created_on_open?mode=memory&cache=shared";
        let older = Connection::open(uri).unwrap();
        older
            .execute_batch("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);")
            .unwrap();
        let absent: i64 = older
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'reviewed'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(absent, 0);
        let opened = Store::open(uri).unwrap();
        assert_eq!(reviewed_rows(&opened.conn), 0);
        assert_eq!(reviewed_rows(&older), 0);
    }

    // A full rebuild keeps the review app's decided pairs.
    #[test]
    fn reset_index_keeps_reviewed() {
        let s = Store::open(":memory:").unwrap();
        s.conn
            .execute(
                "INSERT INTO reviewed (uid, body_hash) VALUES (?, ?)",
                rusqlite::params!["u", "sha256:00"],
            )
            .unwrap();
        s.reset_index().unwrap();
        assert_eq!(reviewed_rows(&s.conn), 1);
    }

    // Puts `qualified` in `src/a.rs` under `hash` and returns its uid; a second
    // call for the same name replaces the bytes, as a re-index does.
    fn unit_with_hash(s: &Store, qualified: &str, hash: &str) -> String {
        let mut unit = sample_unit("src/a.rs", qualified, &format!("crate::{qualified}"));
        unit.body_hash = hash.to_string();
        s.put_unit(&unit).unwrap();
        unit_uid("src/a.rs", Kind::Fn, &unit.qualified)
    }

    fn decide(s: &Store, uid: &str, hash: &str) {
        s.conn
            .execute(
                "INSERT INTO reviewed (uid, body_hash) VALUES (?, ?)",
                rusqlite::params![uid, hash],
            )
            .unwrap();
    }

    fn queue(
        s: &Store,
        uid: &str,
        change: &str,
        old_hash: Option<&str>,
        new_hash: Option<&str>,
        at: i64,
    ) {
        s.conn
            .execute(
                "INSERT INTO change_queue VALUES (?,?,?,?,?,?)",
                rusqlite::params![uid, change, old_hash, new_hash, "cafe", at],
            )
            .unwrap();
    }

    fn open_uids(s: &Store) -> Vec<String> {
        let mut st = s
            .conn
            .prepare("SELECT uid FROM open_units ORDER BY uid")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    type Annotation = (Option<String>, Option<String>, i64);

    // The queue annotation `open_units` gives one listed unit.
    fn annotation(s: &Store, uid: &str) -> Annotation {
        s.conn
            .query_row(
                "SELECT change, old_hash, enqueued_at FROM open_units WHERE uid = ?",
                [uid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
    }

    fn stored_view_sql(conn: &Connection) -> Option<String> {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'view' AND name = 'open_units'",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
    }

    // A decided pair hides a unit only when it names the unit's current bytes.
    #[test]
    fn open_units_excludes_decided_pair() {
        let s = Store::open(":memory:").unwrap();
        let uid = unit_with_hash(&s, "foo", "sha256:aa");
        assert_eq!(open_uids(&s), vec![uid.clone()]);
        decide(&s, &uid, "sha256:stale");
        assert_eq!(
            open_uids(&s),
            vec![uid.clone()],
            "a pair under other bytes decides nothing"
        );
        decide(&s, &uid, "sha256:aa");
        assert!(open_uids(&s).is_empty());
    }

    // Membership comes from `units`, never from the queue: a unit with no
    // queue row is listed, with no change kind, ahead of every queued one.
    #[test]
    fn open_units_lists_unrecorded() {
        let s = Store::open(":memory:").unwrap();
        assert_eq!(s.count("change_queue").unwrap(), 0);
        let uid = unit_with_hash(&s, "foo", "sha256:aa");
        assert_eq!(annotation(&s, &uid), (None, None, 0));
    }

    // The queue annotates a unit only through the row for its current bytes
    // and a pending kind: a row for other bytes, or a `deleted` row, adds
    // nothing and hides nothing.
    #[test]
    fn open_units_annotates_only_from_the_current_pending_row() {
        let s = Store::open(":memory:").unwrap();
        let current = unit_with_hash(&s, "a", "sha256:a1");
        queue(
            &s,
            &current,
            "modified",
            Some("sha256:a0"),
            Some("sha256:a1"),
            7,
        );
        let other_bytes = unit_with_hash(&s, "b", "sha256:b1");
        queue(&s, &other_bytes, "new", None, Some("sha256:b0"), 9);
        let deleted = unit_with_hash(&s, "c", "sha256:c1");
        queue(
            &s,
            &deleted,
            "deleted",
            Some("sha256:c1"),
            Some("sha256:c1"),
            11,
        );
        assert_eq!(open_uids(&s).len(), 3);
        assert_eq!(
            annotation(&s, &current),
            (
                Some("modified".to_string()),
                Some("sha256:a0".to_string()),
                7
            )
        );
        assert_eq!(annotation(&s, &other_bytes), (None, None, 0));
        assert_eq!(annotation(&s, &deleted), (None, None, 0));
    }

    // The view ranges over the units the tree holds now: a vanished unit is
    // not listed whatever the review copy and the queue still hold, and a
    // returning unit is open under new bytes and decided under decided bytes.
    #[test]
    fn open_units_judges_the_tree_as_it_is_now() {
        let s = Store::open(":memory:").unwrap();
        let uid = unit_with_hash(&s, "foo", "sha256:aa");
        decide(&s, &uid, "sha256:aa");
        queue(
            &s,
            &uid,
            "modified",
            Some("sha256:a0"),
            Some("sha256:aa"),
            3,
        );
        s.drop_file("src/a.rs").unwrap();
        assert!(
            open_uids(&s).is_empty(),
            "a vanished unit with a decision and a queue row is not listed"
        );
        assert_eq!(unit_with_hash(&s, "foo", "sha256:bb"), uid);
        assert_eq!(open_uids(&s), vec![uid.clone()], "other bytes are open");
        unit_with_hash(&s, "foo", "sha256:aa");
        assert!(
            open_uids(&s).is_empty(),
            "returning decided bytes stay decided"
        );
    }

    // Each unit is one row however its file, queue and decisions are set up.
    #[test]
    fn open_units_is_one_row_per_unit_with_its_language() {
        let s = Store::open(":memory:").unwrap();
        s.put_file("src/a.rs", "rs", "runtime-rs", 10, "").unwrap();
        let with_file = unit_with_hash(&s, "foo", "sha256:aa");
        queue(&s, &with_file, "new", None, Some("sha256:aa"), 5);
        s.put_unit(&sample_unit("src/b.rs", "bar", "crate::bar"))
            .unwrap();
        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM open_units", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, s.count("units").unwrap());
        let lang = |path: &str| -> Option<String> {
            s.conn
                .query_row("SELECT lang FROM open_units WHERE path = ?", [path], |r| {
                    r.get(0)
                })
                .unwrap()
        };
        assert_eq!(lang("src/a.rs").as_deref(), Some("rs"));
        assert_eq!(lang("src/b.rs"), None);
    }

    // `open` installs the exact text a later `open` compares, so a current
    // view is never rewritten.
    #[test]
    fn open_installs_the_view_text_verbatim() {
        let s = Store::open(":memory:").unwrap();
        assert_eq!(stored_view_sql(&s.conn).as_deref(), Some(OPEN_UNITS_VIEW));
    }

    // The view is always the binary's own definition: one that another
    // binary or a hand edit left behind is replaced on the next open.
    #[test]
    fn open_replaces_a_foreign_view_definition() {
        let uri = "file:open_replaces_a_foreign_view?mode=memory&cache=shared";
        let first = Store::open(uri).unwrap();
        let uid = unit_with_hash(&first, "foo", "sha256:aa");
        first
            .conn
            .execute_batch(
                "DROP VIEW open_units; \
                 CREATE VIEW open_units AS SELECT uid FROM units WHERE 0",
            )
            .unwrap();
        assert!(open_uids(&first).is_empty());
        let second = Store::open(uri).unwrap();
        assert_eq!(open_uids(&second), vec![uid]);
        assert_eq!(
            stored_view_sql(&second.conn).as_deref(),
            Some(OPEN_UNITS_VIEW)
        );
    }

    // An index created before the view and the stamp existed gains both on
    // open.
    #[test]
    fn open_adds_the_view_and_stamp_to_an_older_index() {
        let uri = "file:open_adds_view_and_stamp?mode=memory&cache=shared";
        let older = Connection::open(uri).unwrap();
        older
            .execute_batch("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT);")
            .unwrap();
        let named = |conn: &Connection| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master \
                 WHERE name IN ('open_units', 'reviewed_stamp')",
                [],
                |r| r.get(0),
            )
            .unwrap()
        };
        assert_eq!(named(&older), 0);
        let opened = Store::open(uri).unwrap();
        assert_eq!(named(&opened.conn), 2);
    }

    // The view survives a rebuild and reads the recreated tables.
    #[test]
    fn open_units_survives_reset_index() {
        let s = Store::open(":memory:").unwrap();
        let uid = unit_with_hash(&s, "foo", "sha256:aa");
        decide(&s, &uid, "sha256:aa");
        s.reset_index().unwrap();
        assert!(open_uids(&s).is_empty(), "the units table was emptied");
        let again = unit_with_hash(&s, "foo", "sha256:aa");
        assert!(
            open_uids(&s).is_empty(),
            "the kept decision still hides the re-indexed unit"
        );
        assert_eq!(again, uid);
        let other = unit_with_hash(&s, "bar", "sha256:bb");
        assert_eq!(open_uids(&s), vec![other]);
    }

    // The stamp names the review-database state `reviewed` reflects; a
    // rebuild that dropped it would make the copy look unproven, or worse,
    // proven for a state it no longer matches.
    #[test]
    fn rebuild_keeps_reviewed_stamp() {
        let s = Store::open(":memory:").unwrap();
        s.conn
            .execute(
                "INSERT INTO reviewed_stamp (one, head) VALUES (1, ?)",
                ["genesis:abc"],
            )
            .unwrap();
        s.reset_index().unwrap();
        let head: String = s
            .conn
            .query_row("SELECT head FROM reviewed_stamp WHERE one = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(head, "genesis:abc");
    }

    // One stamp row, its head non-empty text.
    #[test]
    fn reviewed_stamp_holds_one_row_with_a_head() {
        let s = Store::open(":memory:").unwrap();
        let second = s
            .conn
            .execute("INSERT INTO reviewed_stamp (one, head) VALUES (2, 'h')", [])
            .unwrap_err();
        assert!(second.to_string().contains("CHECK"), "got: {second}");
        let headless = s
            .conn
            .execute(
                "INSERT INTO reviewed_stamp (one, head) VALUES (1, NULL)",
                [],
            )
            .unwrap_err();
        assert!(headless.to_string().contains("NOT NULL"), "got: {headless}");
        for head in ["''", "x''", "x'6869'"] {
            let refused = s
                .conn
                .execute(
                    &format!("INSERT INTO reviewed_stamp (one, head) VALUES (1, {head})"),
                    [],
                )
                .unwrap_err();
            assert!(refused.to_string().contains("CHECK"), "{head}: {refused}");
        }
        let rows: i64 = s
            .conn
            .query_row("SELECT COUNT(*) FROM reviewed_stamp", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    // Removes an on-disk test database and its WAL side files.
    struct DbFile(std::path::PathBuf);
    impl Drop for DbFile {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let mut path = self.0.clone().into_os_string();
                path.push(suffix);
                let _ = std::fs::remove_file(path);
            }
        }
    }

    // Opening a current index writes nothing, so a query command opens beside
    // a rebuild that holds the write lock. A rewrite of the view on every open
    // would wait out the busy timeout and fail here.
    #[test]
    fn open_beside_a_held_write_lock_rewrites_nothing() {
        let file = DbFile(ipe_test_temp::temp_root().join(format!(
            "ipe-index-open-beside-write-lock-{}.db",
            std::process::id()
        )));
        drop(DbFile(file.0.clone()));
        let path = file.0.to_str().unwrap();
        let writer = Store::open(path).unwrap();
        let uid = unit_with_hash(&writer, "foo", "sha256:aa");
        writer.begin().unwrap();
        let reader = Store::open(path).unwrap();
        assert_eq!(open_uids(&reader), vec![uid]);
        writer.rollback().unwrap();
    }

    // A root row with an outer tag but no prefix (or the reverse) cannot be
    // stored, so a recorded nesting is always whole.
    #[test]
    fn half_repos_row_rejected_by_schema() {
        let s = Store::open(":memory:").unwrap();
        for half in [
            "INSERT INTO repos VALUES ('in', 'out', NULL)",
            "INSERT INTO repos VALUES ('in', NULL, 'inner')",
        ] {
            assert!(s.conn.execute(half, []).is_err(), "{half}");
        }
        let set = [
            RecordedRoot {
                tag: "out".to_string(),
                nesting: None,
            },
            RecordedRoot {
                tag: "in".to_string(),
                nesting: Some(("out".to_string(), "inner".to_string())),
            },
        ];
        s.record_repos(&set).unwrap();
        let mut want = set.to_vec();
        want.sort();
        assert_eq!(s.recorded_repos().unwrap(), want);
        s.reset_index().unwrap();
        assert_eq!(s.recorded_repos().unwrap(), Vec::new());
    }

    #[test]
    fn count_rejects_unknown_table() {
        let s = Store::open(":memory:").unwrap();
        assert!(s.count("nope").is_err());
    }
}


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
  root   TEXT NOT NULL,
  outer  TEXT,
  prefix TEXT,
  CHECK ((outer IS NULL) = (prefix IS NULL))
);

use crate::repo_set::{LocateRefusal, RepoSet};
use crate::store::Store;
use crate::walk::{ReadRefusal, shown};
use anyhow::Result;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;

/// Escapes `text` so it matches only itself inside a `LIKE ... ESCAPE '\'` pattern.
///
/// The one place a user-typed string becomes pattern text: `%`, `_` and the
/// escape character itself lose their wildcard meaning.
fn like_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A resolved review unit: enough to locate it, judge it, and follow it into
/// the callgraph. The shared shape behind `locate`, `callers`, `callees`, and
/// `context` so a human name resolves once and every command reports the same
/// coordinates.
struct UnitRow {
    uid: String,
    path: String,
    kind: String,
    qualified: String,
    line_start: i64,
    line_end: i64,
    facing: String,
    purpose: Option<String>,
}

/// Resolve a caller-supplied `target` to the units it names. A 64-hex string is
/// treated as a uid (exact). Otherwise it matches a unit's short `name` OR its
/// full `qualified` name, so a reviewer can pass either `Lowerer` or
/// `crate::Lowerer`. Ordered by path then line for stable, clickable output.
fn resolve_units(s: &Store, target: &str) -> Result<Vec<UnitRow>> {
    let is_uid = target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit());
    let sql = if is_uid {
        "SELECT uid, path, kind, qualified, line_start, line_end, facing, purpose \
         FROM units WHERE uid = ?1 ORDER BY path, line_start"
    } else {
        "SELECT uid, path, kind, qualified, line_start, line_end, facing, purpose \
         FROM units WHERE name = ?1 OR qualified = ?1 ORDER BY path, line_start"
    };
    let mut st = s.conn.prepare(sql)?;
    let rows = st.query_map([target], |r| {
        Ok(UnitRow {
            uid: r.get(0)?,
            path: r.get(1)?,
            kind: r.get(2)?,
            qualified: r.get(3)?,
            line_start: r.get(4)?,
            line_end: r.get(5)?,
            facing: r.get(6)?,
            purpose: r.get(7)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// `locate <name>`: every def/impl site of a symbol as `file:line:col  kind`.
/// Each line is appended with the unit's uid and qualified name when the site
/// corresponds to a reviewable unit, so a reviewer can pipe the uid straight
/// into `callers`/`callees`/`context` without a second lookup.
pub fn cmd_locate(db: &str, name: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();

    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }

    // Map (path, line, kind) → (uid, qualified) so a symbol site can carry the
    // unit coordinates a reviewer needs to follow it into the callgraph. `def`
    // symbols line up with a unit at the same start line; `impl` symbols with
    // an `impl` unit.
    let mut unit_at: HashMap<(String, i64, String), (String, String)> = HashMap::new();
    {
        let mut st = s
            .conn
            .prepare("SELECT path, line_start, kind, uid, qualified FROM units")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (path, line, kind, uid, qualified) = row?;
            unit_at.insert((path, line, kind), (uid, qualified));
        }
    }

    let sym_rows: Vec<(String, i64, i64, String)> = {
        let mut st = s.conn.prepare(
            "SELECT file, line, col, kind FROM symbols WHERE name=? ORDER BY file, line",
        )?;
        st.query_map([name], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<std::result::Result<_, _>>()?
    };
    let mut found = false;
    for (file, line, col, kind) in sym_rows {
        // A symbol `def`/`impl` maps to a unit of the matching kind; `def`
        // covers fn/struct/enum/trait/const/binding units, so try each.
        let unit = if kind == "impl" {
            unit_at.get(&(file.clone(), line, "impl".to_string()))
        } else {
            [
                "fn", "struct", "enum", "trait", "const", "binding", "module",
            ]
            .iter()
            .find_map(|k| unit_at.get(&(file.clone(), line, k.to_string())))
        };
        match unit {
            Some((uid, qualified)) => {
                writeln_bp!("{file}:{line}:{col}  {kind}  {qualified}  {uid}")
            }
            None => writeln_bp!("{file}:{line}:{col}  {kind}"),
        }
        found = true;
    }
    if !found {
        writeln_bp!("(no results for {name:?})");
    }
    Ok(())
}

/// One `file:line-line  kind  qualified  [uid]` line for a resolved unit — the
/// concise, clickable review coordinate shared by the blast-radius commands.
fn unit_line(u: &UnitRow) -> String {
    format!(
        "{}:{}-{}  {}  {}  {}",
        u.path, u.line_start, u.line_end, u.kind, u.qualified, u.uid
    )
}

/// `callers <name-or-uid>`: every unit that calls the target — the inbound
/// blast radius a reviewer needs to answer "who breaks if this changes?".
/// Resolves a human name to its unit(s) first, so no uid is required.
pub fn cmd_callers(db: &str, target: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }
    let targets = resolve_units(&s, target)?;
    if targets.is_empty() {
        writeln_bp!("(no unit matches {target:?})");
        return Ok(());
    }
    let mut any = false;
    let mut st = s.conn.prepare(
        "SELECT u.path, u.line_start, u.line_end, u.kind, u.qualified, u.uid \
         FROM callgraph c JOIN units u ON u.uid = c.caller_uid \
         WHERE c.callee_uid = ?1 ORDER BY u.path, u.line_start",
    )?;
    for t in &targets {
        if targets.len() > 1 {
            writeln_bp!("# callers of {} ({})", t.qualified, t.uid);
        }
        let rows = st.query_map([&t.uid], |r| {
            Ok(UnitRow {
                path: r.get(0)?,
                line_start: r.get(1)?,
                line_end: r.get(2)?,
                kind: r.get(3)?,
                qualified: r.get(4)?,
                uid: r.get(5)?,
                facing: String::new(),
                purpose: None,
            })
        })?;
        for row in rows {
            writeln_bp!("{}", unit_line(&row?));
            any = true;
        }
    }
    if !any {
        writeln_bp!("(no callers)");
    }
    Ok(())
}

/// `callees <name-or-uid>`: every unit the target calls — the outbound
/// dependencies a reviewer checks to judge what a change relies on.
pub fn cmd_callees(db: &str, target: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }
    let targets = resolve_units(&s, target)?;
    if targets.is_empty() {
        writeln_bp!("(no unit matches {target:?})");
        return Ok(());
    }
    let mut any = false;
    let mut st = s.conn.prepare(
        "SELECT u.path, u.line_start, u.line_end, u.kind, u.qualified, u.uid \
         FROM callgraph c JOIN units u ON u.uid = c.callee_uid \
         WHERE c.caller_uid = ?1 ORDER BY u.path, u.line_start",
    )?;
    for t in &targets {
        if targets.len() > 1 {
            writeln_bp!("# callees of {} ({})", t.qualified, t.uid);
        }
        let rows = st.query_map([&t.uid], |r| {
            Ok(UnitRow {
                path: r.get(0)?,
                line_start: r.get(1)?,
                line_end: r.get(2)?,
                kind: r.get(3)?,
                qualified: r.get(4)?,
                uid: r.get(5)?,
                facing: String::new(),
                purpose: None,
            })
        })?;
        for row in rows {
            writeln_bp!("{}", unit_line(&row?));
            any = true;
        }
    }
    if !any {
        writeln_bp!("(no callees)");
    }
    Ok(())
}

/// `context <name-or-uid>`: the at-a-glance review card for a unit — location,
/// kind/facing, purpose, and caller/callee counts — so a reviewer can judge a
/// change without opening the file.
pub fn cmd_context(db: &str, target: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }
    let targets = resolve_units(&s, target)?;
    if targets.is_empty() {
        writeln_bp!("(no unit matches {target:?})");
        return Ok(());
    }
    for t in &targets {
        let callers: i64 = s.conn.query_row(
            "SELECT COUNT(*) FROM callgraph WHERE callee_uid = ?1",
            [&t.uid],
            |r| r.get(0),
        )?;
        let callees: i64 = s.conn.query_row(
            "SELECT COUNT(*) FROM callgraph WHERE caller_uid = ?1",
            [&t.uid],
            |r| r.get(0),
        )?;
        writeln_bp!("{} [{}, {}]", t.qualified, t.kind, t.facing);
        writeln_bp!("  at   {}:{}-{}", t.path, t.line_start, t.line_end);
        writeln_bp!("  uid  {}", t.uid);
        if let Some(p) = &t.purpose {
            writeln_bp!("  doc  {p}");
        }
        writeln_bp!("  blast {callers} caller(s), {callees} callee(s)");
    }
    Ok(())
}

/// Why `changed` will not diff the directory it was pointed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedRefusal {
    /// The directory is no root of the set this index was built under.
    NotARecordedRoot { dir: String },
}

impl fmt::Display for ChangedRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotARecordedRoot { dir } => write!(
                f,
                "--repo `{}` is none of the roots this index was built from",
                shown(dir)
            ),
        }
    }
}

impl std::error::Error for ChangedRefusal {}

/// The units of one tagged path that a changed line range overlaps.
fn units_in_ranges(
    st: &mut rusqlite::Statement<'_>,
    tagged: &str,
    ranges: &[(i64, i64)],
) -> Result<Vec<UnitRow>> {
    let rows: Vec<UnitRow> = st
        .query_map([tagged], |r| {
            Ok(UnitRow {
                uid: r.get(0)?,
                path: r.get(1)?,
                kind: r.get(2)?,
                qualified: r.get(3)?,
                line_start: r.get(4)?,
                line_end: r.get(5)?,
                facing: r.get(6)?,
                purpose: r.get(7)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(rows
        .into_iter()
        .filter(|u| {
            ranges
                .iter()
                .any(|(a, b)| u.line_start <= *b && *a <= u.line_end)
        })
        .collect())
}

/// The units of `repo`'s diff over `range`: those a changed line range overlaps.
///
/// `repo` must be a root of the recorded set; a path changed under a root
/// nested in it belongs to the nested root's tag.
fn changed_units(s: &Store, repo: &str, range: &str) -> Result<Vec<UnitRow>> {
    let set = s.repo_set()?;
    let Some(root) = set.root_at_dir(repo) else {
        return Err(ChangedRefusal::NotARecordedRoot {
            dir: repo.to_string(),
        }
        .into());
    };
    // The changed line ranges per file, from git — the source of truth for
    // which units a diff overlaps.
    let hunks = crate::diff::changed_line_ranges(root, range)?;
    let mut st = s.conn.prepare(
        "SELECT uid, path, kind, qualified, line_start, line_end, facing, purpose \
         FROM units WHERE path = ?1 AND kind != 'file' \
         ORDER BY line_start",
    )?;
    let mut found = Vec::new();
    for (rel, ranges) in &hunks {
        let (owner, below) = set.owner_of(root, rel);
        found.extend(units_in_ranges(
            &mut st,
            &owner.tag().tagged(below),
            ranges,
        )?);
    }
    Ok(found)
}

/// `changed <git-range>`: the review entry point for a branch/PR. Lists the
/// units that fall inside the changed line ranges of `<range>` (e.g.
/// `main..HEAD`), each as a concise clickable coordinate, so a reviewer sees
/// exactly which symbols a diff touched — not just which files. Read-only.
pub fn cmd_changed(db: &str, repo: &str, range: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let units = changed_units(&s, repo, range)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }
    for u in &units {
        writeln_bp!("{}", unit_line(u));
    }
    if units.is_empty() {
        writeln_bp!("(no changed units in {range})");
    }
    Ok(())
}

pub fn cmd_rdeps(db: &str, module: &str, count: bool, subtree: bool) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let sources = rdeps_sources(&s, module, subtree)?;
    if count {
        println!("{}", sources.len());
        return Ok(());
    }
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    for src in sources {
        if let Err(e) = writeln!(locked, "{src}") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                return Ok(());
            }
            return Err(e.into());
        }
    }
    Ok(())
}

/// The files importing `module`, sorted and distinct.
///
/// - an exact `dst` match (default);
/// - also an exact `resolved` match when `module` is path-shaped (holds a `/`
///   or a `.`);
/// - `subtree`: also every dotted module below `module`, whole segments only.
///
/// No match is unanchored, so `rdeps "List"` never folds in `Data.List`,
/// `container/list`, or `*ListSpec` files. A SQL `LIKE` is ASCII
/// case-insensitive, so the subtree rows it selects are filtered again by an
/// exact, case-sensitive comparison.
fn rdeps_sources(s: &Store, module: &str, subtree: bool) -> Result<BTreeSet<String>> {
    let looks_like_path = module.contains('/') || module.contains('.');
    let mut sources = BTreeSet::new();
    if subtree {
        let mut st = s.conn.prepare(
            "SELECT src, dst, resolved FROM edges \
             WHERE kind='import' AND (dst=?1 OR dst LIKE ?2 ESCAPE '\\' OR resolved=?1)",
        )?;
        let rows = st.query_map(
            rusqlite::params![module, format!("{}.%", like_literal(module))],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                ))
            },
        )?;
        for row in rows {
            let (src, dst, resolved) = row?;
            if resolved.as_deref() == Some(module) || below_module(&dst, module).is_some() {
                sources.insert(src);
            }
        }
        return Ok(sources);
    }
    let sql = if looks_like_path {
        "SELECT DISTINCT src FROM edges WHERE kind='import' AND (dst=?1 OR resolved=?1)"
    } else {
        "SELECT DISTINCT src FROM edges WHERE kind='import' AND dst=?1"
    };
    let mut st = s.conn.prepare(sql)?;
    for src in st.query_map([module], |r| r.get::<_, String>(0))? {
        sources.insert(src?);
    }
    Ok(sources)
}

pub fn cmd_deps(db: &str, module: &str) -> Result<()> {
    let s = Store::open(db)?;
    // NOTE: deliberately unanchored substring match (the CLI documents `deps` as
    // "substring match"). `?1` is bound as a parameter, so this is injection-safe;
    // the looseness — `deps "List"` folding in any path containing "List" — is the
    // documented CLI contract, not a bug. Use `rdeps` for exact dst/resolved match.
    // Only the surrounding `%` are wildcards: `module` itself is matched literally.
    let mut st = s.conn.prepare(
        "SELECT DISTINCT dst FROM edges WHERE src LIKE ?1 ESCAPE '\\' AND kind='import' ORDER BY dst",
    )?;
    let rows = st.query_map([format!("%{}%", like_literal(module))], |r| {
        r.get::<_, String>(0)
    })?;
    for r in rows {
        println!("{}", r?);
    }
    Ok(())
}

pub fn cmd_roles(db: &str) -> Result<()> {
    let s = Store::open(db)?;
    let mut st = s
        .conn
        .prepare("SELECT role,COUNT(*) FROM files GROUP BY role ORDER BY 2 DESC")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for r in rows {
        let (role, n) = r?;
        println!("{role:<14} {n}");
    }
    Ok(())
}

pub fn cmd_pipeline(db: &str) -> Result<()> {
    let s = Store::open(db)?;
    let mut st = s.conn.prepare(
        "SELECT dst,COUNT(*) FROM edges WHERE kind='in-stage' GROUP BY dst ORDER BY 2 DESC",
    )?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    for r in rows {
        let (st_, n) = r?;
        println!("{st_:<14} {n} modules");
    }
    Ok(())
}

pub fn cmd_covers(db: &str, kernel: &str) -> Result<()> {
    let s = Store::open(db)?;
    // Unanchored substring match by design (the CLI documents `covers` as
    // "substring match"); `?1` is a bound parameter so it stays injection-safe.
    let mut st = s.conn.prepare(
        "SELECT src FROM edges WHERE kind='covers' AND dst LIKE ?1 ESCAPE '\\' ORDER BY src",
    )?;
    let rows = st.query_map([format!("%{}%", like_literal(kernel))], |r| {
        r.get::<_, String>(0)
    })?;
    for r in rows {
        println!("{}", r?);
    }
    Ok(())
}

pub fn cmd_wakeup(db: &str) -> Result<()> {
    let s = Store::open(db)?;
    println!("# ipe-index digest");
    println!("files: {}", s.count("files")?);
    println!(
        "symbols: {}, edges: {}",
        s.count("symbols")?,
        s.count("edges")?,
    );
    cmd_roles(db)
}

/// Resolution pass: for every import edge, try to resolve `dst` to a canonical
/// file path within the repo. Updates `edges.resolved` in a single transaction.
/// Bounded: loads tracked file paths into a HashSet (bounded by file count);
/// buffers unresolved import edges into a Vec (bounded by import-edge count)
/// to work around the borrow-checker's prohibition on simultaneous read and
/// write `Connection` statements — the buffer is freed after all UPDATEs commit.
pub fn resolve_edges(s: &Store, repo: &str) -> Result<()> {
    // Load all known file paths into a set for fast membership test.
    let mut known: HashSet<String> = HashSet::new();
    {
        let mut st = s.conn.prepare("SELECT path FROM files")?;
        for row in st.query_map([], |r| r.get::<_, String>(0))? {
            known.insert(row?);
        }
    }
    // Collect rows to update (buffered to avoid borrow-checker issue with conn:
    // rusqlite does not permit a prepared SELECT and an execute() on the same
    // Connection simultaneously; the buffer is bounded by import-edge count).
    let to_update: Vec<(i64, String, String, String)> = {
        let mut st = s.conn.prepare(
            "SELECT rowid, src, dst, kind FROM edges WHERE kind='import' AND resolved IS NULL",
        )?;

        st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };

    // Use unchecked_transaction only if not already inside a transaction.
    // When called from cmd_index (inside BEGIN/COMMIT), we can write directly.
    // SAFETY of `unchecked_transaction`: the SELECT result above is fully
    // materialised into `to_update` BEFORE any write below, so no prepared
    // statement is live on `conn` during the UPDATEs. Do NOT reorder to stream
    // rows from a live statement into the writes — that would alias `conn`.
    let is_autocommit = s.conn.is_autocommit();
    if is_autocommit {
        // Not in a transaction — wrap in one for efficiency.
        let tx = s.conn.unchecked_transaction()?;
        for (rowid, src, dst, _kind) in to_update {
            if let Some(resolved) = resolve_import(&src, &dst, repo, &known) {
                tx.execute(
                    "UPDATE edges SET resolved=? WHERE rowid=?",
                    rusqlite::params![resolved, rowid],
                )?;
            }
        }
        tx.commit()?;
    } else {
        // Already inside a transaction (e.g., cmd_index's BEGIN). Write directly.
        for (rowid, src, dst, _kind) in to_update {
            if let Some(resolved) = resolve_import(&src, &dst, repo, &known) {
                s.conn.execute(
                    "UPDATE edges SET resolved=? WHERE rowid=?",
                    rusqlite::params![resolved, rowid],
                )?;
            }
        }
    }
    Ok(())
}

/// Attempt to resolve one import edge to a canonical repo-relative path.
/// Returns `None` if the import is external (npm pkg, go module, etc.) or
/// cannot be reliably determined.
fn resolve_import(src: &str, dst: &str, repo: &str, known: &HashSet<String>) -> Option<String> {
    // Determine language from source extension.
    let src_ext = std::path::Path::new(src)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let _ = repo;
    match src_ext {
        // ── Ipê modules ───────────────────────────────────────────────────────
        "ipe" => resolve_module_style(dst, known),

        // ── TypeScript / JavaScript ───────────────────────────────────────────
        "ts" | "tsx" | "js" | "mjs" | "jsx" => {
            if dst.starts_with('.') {
                resolve_relative_js(src, dst, known)
            } else {
                None // npm package — external
            }
        }

        // ── Rust ──────────────────────────────────────────────────────────────
        "rs" => resolve_rust_import(src, dst, known),

        _ => None,
    }
}

/// Resolve a dotted `.ipe` module name like `Ipe.Core.List` to a file path.
fn resolve_module_style(module: &str, known: &HashSet<String>) -> Option<String> {
    // `Ipe.Core.List` → `Ipe/Core/List`
    let slash_path = module.replace('.', "/");
    let candidate = format!("{slash_path}.ipe");
    if known.contains(&candidate) {
        return Some(candidate);
    }
    // Also check under a `src/` prefix (an app's module tree).
    let with_src = format!("src/{slash_path}.ipe");
    if known.contains(&with_src) {
        return Some(with_src);
    }
    None
}

/// Resolve a relative JS/TS import like `./bar` or `../util/helper`.
fn resolve_relative_js(src: &str, dst: &str, known: &HashSet<String>) -> Option<String> {
    let src_dir = std::path::Path::new(src).parent()?;
    let raw = src_dir.join(dst);
    // Normalise the path (remove .., .) without requiring the path to exist on disk.
    let normalised = normalise_path(&raw);
    // Try each extension, then index file variants.
    let exts = ["ts", "tsx", "js", "mjs", "jsx"];
    for ext in &exts {
        let cand = format!("{normalised}.{ext}");
        if known.contains(&cand) {
            return Some(cand);
        }
    }
    // index file inside a directory.
    for ext in &exts {
        let cand = format!("{normalised}/index.{ext}");
        if known.contains(&cand) {
            return Some(cand);
        }
    }
    // Already has an extension?
    if known.contains(&normalised) {
        return Some(normalised);
    }
    None
}

/// Normalise a path by resolving `..` and `.` components lexically.
fn normalise_path(p: &std::path::Path) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for comp in p.components() {
        use std::path::Component::*;
        match comp {
            Normal(s) => parts.push(s.to_str().unwrap_or("")),
            ParentDir => {
                parts.pop();
            }
            CurDir => {}
            RootDir => parts.clear(),
            Prefix(_) => {}
        }
    }
    parts.join("/")
}

/// Resolve a Rust `use` path to a source file.
/// `crate::a::b` → strip `crate::`, try `a/b.rs` or `a/b/mod.rs` relative to
/// the crate's src root (inferred from `src` file location).
/// External crates (`::` paths not starting with `crate` / `super` / `self`)
/// → None.
fn resolve_rust_import(src: &str, dst: &str, known: &HashSet<String>) -> Option<String> {
    // External crate reference: doesn't start with crate/super/self.
    let first_seg = dst.split("::").next().unwrap_or("");
    if first_seg != "crate" && first_seg != "super" && first_seg != "self" && !first_seg.is_empty()
    {
        return None;
    }

    // Find the crate root (directory containing Cargo.toml, inferred as parent of `src/`).
    let src_path = std::path::Path::new(src);
    let crate_root = find_crate_root(src_path)?;

    // Build candidate path segments by stripping `crate::` and splitting on `::`.
    let rel = if let Some(stripped) = dst.strip_prefix("crate::") {
        stripped
    } else if dst.starts_with("super::") {
        // super:: refers to parent module — too ambiguous to resolve reliably.
        return None;
    } else {
        dst
    };

    let parts: Vec<&str> = rel.split("::").collect();
    let slash_path = parts.join("/");
    let base = format!("{crate_root}/{slash_path}");

    // Try file.rs then file/mod.rs.
    let as_file = format!("{base}.rs");
    if known.contains(&as_file) {
        return Some(as_file);
    }
    let as_mod = format!("{base}/mod.rs");
    if known.contains(&as_mod) {
        return Some(as_mod);
    }
    None
}

/// Find the nearest ancestor directory that looks like a Rust crate root (has a `src/` child
/// in the known file set). Returns the repo-relative prefix for that crate root.
fn find_crate_root(src_file: &std::path::Path) -> Option<String> {
    // Walk up from the file's directory looking for `src/` parent.
    let mut dir = src_file.parent()?;
    loop {
        let dir_str = dir.to_str().unwrap_or("");
        // If the current directory is named `src`, its parent is the crate root.
        if dir.file_name().and_then(|n| n.to_str()) == Some("src") {
            let parent = dir.parent().unwrap_or(std::path::Path::new(""));
            let parent_str = parent.to_str().unwrap_or("");
            return Some(if parent_str.is_empty() {
                "src".to_string()
            } else {
                format!("{parent_str}/src")
            });
        }
        // Stopping condition: we've hit the root.
        if dir_str.is_empty() || dir == std::path::Path::new("") {
            break;
        }
        dir = match dir.parent() {
            Some(p) => p,
            None => break,
        };
    }
    None
}

/// `links <uid>`: outgoing links and callgraph calls of one unit.
/// Internal link targets resolve to the callee unit's qualified name (via the
/// `to_uid` join); external refs keep the raw URL. One text line per row.
pub fn cmd_links(db: &str, uid: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();

    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }

    let mut any = false;
    let mut st = s.conn.prepare(
        "SELECT l.to_kind, COALESCE(u.qualified, l.to_ref), l.line \
         FROM links l LEFT JOIN units u ON u.uid = l.to_uid \
         WHERE l.from_uid = ?1 ORDER BY l.line, l.to_kind",
    )?;
    let rows = st.query_map([uid], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    for r in rows {
        let (kind, target, line) = r?;
        writeln_bp!("{kind:<8} {target} (line {line})");
        any = true;
    }
    let mut st = s.conn.prepare(
        "SELECT u.qualified FROM callgraph c JOIN units u ON u.uid = c.callee_uid \
         WHERE c.caller_uid = ?1 ORDER BY u.qualified",
    )?;
    let rows = st.query_map([uid], |r| r.get::<_, String>(0))?;
    for r in rows {
        writeln_bp!("call     {}", r?);
        any = true;
    }
    if !any {
        writeln_bp!("(no links or calls for {uid})");
    }
    Ok(())
}

/// `neighbors <uid>`: links + callgraph edges in BOTH directions around a
/// unit. `link-out`/`call` originate at the unit; `link-in`/`called-by` point
/// at it. One text line per row.
pub fn cmd_neighbors(db: &str, uid: &str) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();

    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }

    let mut st = s.conn.prepare(
        "SELECT 'link-out', COALESCE(u.qualified, l.to_ref), l.line \
         FROM links l LEFT JOIN units u ON u.uid = l.to_uid \
         WHERE l.from_uid = ?1 \
         UNION ALL \
         SELECT 'link-in', COALESCE(u.qualified, l.to_ref), l.line \
         FROM links l LEFT JOIN units u ON u.uid = l.from_uid \
         WHERE l.to_uid = ?1 \
         UNION ALL \
         SELECT 'call', u.qualified, 0 \
         FROM callgraph c JOIN units u ON u.uid = c.callee_uid WHERE c.caller_uid = ?1 \
         UNION ALL \
         SELECT 'called-by', u.qualified, 0 \
         FROM callgraph c JOIN units u ON u.uid = c.caller_uid WHERE c.callee_uid = ?1 \
         ORDER BY 1, 3, 2",
    )?;
    let rows = st.query_map([uid], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })?;
    let mut any = false;
    for r in rows {
        let (dir, target, line) = r?;
        writeln_bp!("{dir:<9} {target} (line {line})");
        any = true;
    }
    if !any {
        writeln_bp!("(no neighbors for {uid})");
    }
    Ok(())
}

/// `pending`: change-queue rows as JSON lines (one object per queued unit).
/// `--since <sha>` excludes rows enqueued by that update run (empty matches
/// everything); `--limit N` caps the result. Deleted units join to NULL unit
/// columns (their `units` row is gone), so `qualified`/`path`/`kind` are null.
pub fn cmd_pending(db: &str, since: Option<&str>, limit: Option<i64>) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    let stdout = std::io::stdout();
    let mut locked = stdout.lock();

    macro_rules! writeln_bp {
        ($($arg:tt)*) => {
            if let Err(e) = writeln!(locked, $($arg)*) {
                if e.kind() == std::io::ErrorKind::BrokenPipe { return Ok(()); }
                return Err(e.into());
            }
        };
    }

    // `?1 = ''` short-circuits when no --since was given (match all rows).
    // Ordering: modified first, then new, then deleted; ties by enqueue time.
    // `LIMIT -1` is SQLite's "no upper bound" — binding NULL would raise a
    // datatype-mismatch error, so an absent --limit becomes -1.
    let since_str = since.unwrap_or("");
    let limit_val = limit.unwrap_or(-1);
    let mut st = s.conn.prepare(
        "SELECT q.uid, q.change, q.old_hash, q.new_hash, q.enqueued_sha, q.enqueued_at, \
                u.qualified, u.path, u.kind \
         FROM change_queue q LEFT JOIN units u ON u.uid = q.uid \
         WHERE (?1 = '' OR q.enqueued_sha != ?1) \
         ORDER BY CASE q.change WHEN 'modified' THEN 0 WHEN 'new' THEN 1 ELSE 2 END, \
                  q.enqueued_at, q.uid \
         LIMIT ?2",
    )?;
    let rows = st.query_map(rusqlite::params![since_str, limit_val], |r| {
        Ok(serde_json::json!({
            "uid": r.get::<_, String>(0)?,
            "change": r.get::<_, String>(1)?,
            "old_hash": r.get::<_, Option<String>>(2)?,
            "new_hash": r.get::<_, Option<String>>(3)?,
            "enqueued_sha": r.get::<_, String>(4)?,
            "enqueued_at": r.get::<_, i64>(5)?,
            "qualified": r.get::<_, Option<String>>(6)?,
            "path": r.get::<_, Option<String>>(7)?,
            "kind": r.get::<_, Option<String>>(8)?,
        }))
    })?;
    for r in rows {
        writeln_bp!("{}", serde_json::to_string(&r?)?);
    }
    Ok(())
}

/// The match patterns for a stored (repo-tagged) path column.
///
/// Stored paths are `tag:rel`, but a caller types the untagged `rel`, so the
/// four patterns select the exact rel and its subtree, tagged or not. The
/// first is compared with `=`; the others are `LIKE ... ESCAPE '\'` patterns
/// over the escaped name. They only narrow the scan: [`names_path`] decides.
fn path_match_patterns(old: &str) -> (String, String, String, String) {
    let literal = like_literal(old);
    (
        old.to_string(),
        format!("%:{literal}"),
        format!("{literal}/%"),
        format!("%:{literal}/%"),
    )
}

/// Whether the rel after the stored path's tag is `old` or a path below it.
///
/// Whole segments only, and case-sensitive, which a SQL `LIKE` is not.
fn names_path(stored: &str, old: &str) -> bool {
    let (_, rel) = crate::model::split_tag(stored);
    rel == old
        || rel
            .strip_prefix(old)
            .is_some_and(|below| below.starts_with('/'))
}

/// Splice a whole-segment path rename onto a stored (possibly tagged) path,
/// preserving the `tag:` prefix. `old` matches the untagged rel; the tag and
/// any trailing subtree are re-attached around the replacement.
fn splice_path(stored: &str, old: &str, to: &str) -> String {
    let (tag, rel) = crate::model::split_tag(stored);
    let new_rel = if rel == old {
        to.to_string()
    } else if let Some(suffix) = rel.strip_prefix(&format!("{old}/")) {
        format!("{to}/{suffix}")
    } else {
        // Not a whole-segment match of `old`: leave it unchanged rather than
        // corrupt the path.
        rel.to_string()
    };
    if tag.is_empty() {
        new_rel
    } else {
        format!("{tag}:{new_rel}")
    }
}

/// What follows `old` in `name` when `name` is `old` or a dotted path below it.
fn below_module<'a>(name: &'a str, old: &str) -> Option<&'a str> {
    let rest = name.strip_prefix(old)?;
    (rest.is_empty() || rest.starts_with('.')).then_some(rest)
}

/// The tail an import edge carries onto its replacement: empty for `old` itself.
fn edge_tail<'a>(dst: &'a str, resolved: Option<&'a str>, old: &str) -> Option<&'a str> {
    if dst == old || resolved == Some(old) {
        return Some("");
    }
    below_module(dst, old).or_else(|| resolved.and_then(|r| below_module(r, old)))
}

/// The sites a whole-segment rename of `old` touches, sorted.
fn rename_path_sites(s: &Store, old: &str, to: Option<&str>) -> Result<Vec<serde_json::Value>> {
    let mut sites = Vec::new();
    let (p_exact, p_exact_tag, p_sub, p_sub_tag) = path_match_patterns(old);

    // files.path — exact or subtree, tagged or not.
    {
        let mut st = s.conn.prepare(
            "SELECT path FROM files WHERE path = ?1 OR path LIKE ?2 ESCAPE '\\' OR path LIKE ?3 ESCAPE '\\' OR path LIKE ?4 ESCAPE '\\'",
        )?;
        let rows = st.query_map(
            rusqlite::params![p_exact, p_exact_tag, p_sub, p_sub_tag],
            |r| r.get::<_, String>(0),
        )?;
        for r in rows {
            let path = r?;
            if !names_path(&path, old) {
                continue;
            }
            let replacement = to.map(|t| splice_path(&path, old, t));
            sites.push(serde_json::json!({
                "kind": "file",
                "path": path,
                "line": 0,
                "col": 0,
                "context": path,
                "replacement": replacement,
            }));
        }
    }

    // symbols.file — exact or subtree, tagged or not.
    {
        let mut st = s.conn.prepare(
            "SELECT file, line, col, name FROM symbols WHERE file = ?1 OR file LIKE ?2 ESCAPE '\\' OR file LIKE ?3 ESCAPE '\\' OR file LIKE ?4 ESCAPE '\\'",
        )?;
        let rows = st.query_map(
            rusqlite::params![p_exact, p_exact_tag, p_sub, p_sub_tag],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )?;
        for r in rows {
            let (file, line, col, name) = r?;
            if !names_path(&file, old) {
                continue;
            }
            let replacement = to.map(|t| splice_path(&file, old, t));
            sites.push(serde_json::json!({
                "kind": "symbol",
                "path": file,
                "line": line,
                "col": col,
                "context": name,
                "replacement": replacement,
            }));
        }
    }

    // units.path — exact or subtree, tagged or not.
    {
        let mut st = s.conn.prepare(
            "SELECT path, line_start, qualified FROM units WHERE path = ?1 OR path LIKE ?2 ESCAPE '\\' OR path LIKE ?3 ESCAPE '\\' OR path LIKE ?4 ESCAPE '\\'",
        )?;
        let rows = st.query_map(
            rusqlite::params![p_exact, p_exact_tag, p_sub, p_sub_tag],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?;
        for r in rows {
            let (path, line, qualified) = r?;
            if !names_path(&path, old) {
                continue;
            }
            let replacement = to.map(|t| splice_path(&path, old, t));
            sites.push(serde_json::json!({
                "kind": "unit",
                "path": path,
                "line": line,
                "col": 0,
                "context": qualified,
                "replacement": replacement,
            }));
        }
    }

    // import edges: dst or resolved is old, or a dotted path below it.
    {
        let mut st = s.conn.prepare(
            "SELECT src, dst, resolved FROM edges WHERE kind='import' AND (dst = ?1 OR resolved = ?1 OR dst LIKE ?2 ESCAPE '\\' OR resolved LIKE ?2 ESCAPE '\\')",
        )?;
        let below = format!("{}.%", like_literal(old));
        let rows = st.query_map([old, below.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        for r in rows {
            let (src, dst, resolved) = r?;
            let Some(tail) = edge_tail(&dst, resolved.as_deref(), old) else {
                continue;
            };
            let replacement = to.map(|t| format!("{t}{tail}"));
            sites.push(serde_json::json!({
                "kind": "import",
                "path": src,
                "line": 0,
                "col": 0,
                "context": dst,
                "replacement": replacement,
            }));
        }
    }

    // links.to_ref is old, or a dotted path below it (join units for path/line).
    {
        let mut st = s.conn.prepare(
            "SELECT l.to_ref, u.path, l.line FROM links l JOIN units u ON u.uid = l.from_uid WHERE l.to_ref = ?1 OR l.to_ref LIKE ?2 ESCAPE '\\'",
        )?;
        let below = format!("{}.%", like_literal(old));
        let rows = st.query_map([old, below.as_str()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for r in rows {
            let (to_ref, path, line) = r?;
            let Some(tail) = below_module(&to_ref, old) else {
                continue;
            };
            let replacement = to.map(|t| format!("{t}{tail}"));
            sites.push(serde_json::json!({
                "kind": "link",
                "path": path,
                "line": line,
                "col": 0,
                "context": to_ref,
                "replacement": replacement,
            }));
        }
    }

    // Sort for deterministic output
    sites.sort_by(|a, b| {
        let a_path = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let b_path = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let a_line = a.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
        let b_line = b.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
        let a_kind = a.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let b_kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let a_ctx = a.get("context").and_then(|v| v.as_str()).unwrap_or("");
        let b_ctx = b.get("context").and_then(|v| v.as_str()).unwrap_or("");
        a_path
            .cmp(b_path)
            .then(a_line.cmp(&b_line))
            .then(a_kind.cmp(b_kind))
            .then(a_ctx.cmp(b_ctx))
    });
    Ok(sites)
}

/// `rename-path <old> [--to <new>]`: whole-segment path match across
/// files, symbols, units, import edges (dst/resolved), and links (to_ref).
/// Outputs JSON lines: {kind,path,line,col,context,replacement?}.
/// kind ∈ {file,symbol,unit,import,link}. Read-only.
pub fn cmd_rename_path(db: &str, old: &str, to: Option<&str>) -> Result<()> {
    let s = Store::open(db)?;
    let sites = rename_path_sites(&s, old, to)?;
    if let Err(e) = write_sites(&sites)
        && e.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(e.into());
    }
    Ok(())
}

/// Why a unit's source gave no lines to scan.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SourceRefusal {
    /// The stored path names no readable place in the recorded root set.
    Locate(LocateRefusal),
    /// The owning root refused the file.
    Read(ReadRefusal),
    /// The unit's recorded lines end past the end of the file as it is now.
    SpanPastFile {
        line_start: i64,
        line_end: i64,
        lines: usize,
    },
    /// A recorded or computed line or column number is outside the line-count range.
    LineNumber,
}

impl fmt::Display for SourceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Locate(why) => write!(f, "{why}"),
            Self::Read(why) => write!(f, "{why}"),
            Self::SpanPastFile {
                line_start,
                line_end,
                lines,
            } => write!(
                f,
                "a unit spans lines {line_start}-{line_end}, past the {lines} lines the file has now; re-run `index`"
            ),
            Self::LineNumber => f.write_str("a line or column number is out of range"),
        }
    }
}

/// A file the rename plan could not read, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnreadFile {
    path: String,
    why: SourceRefusal,
}

/// The sites a rename found, and the files whose lines it could not scan.
///
/// A plan with unread files is incomplete and never presented as complete.
struct RenamePlan {
    sites: Vec<serde_json::Value>,
    unread: Vec<UnreadFile>,
}

/// The lines of a unit's file, read through the root that owns its tagged path.
///
/// Split as the index split them when it recorded the unit spans, so a span
/// and the lines it is checked against count lines the same way.
fn source_lines(set: &RepoSet, tagged: &str) -> Result<Vec<String>, SourceRefusal> {
    let (root, rel) = set.locate(tagged).map_err(SourceRefusal::Locate)?;
    crate::walk::read_owned(root.root(), rel.as_str(), &set.claimed_in(root))
        .map(|text| {
            crate::extract::view::view_lines(&text)
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .map_err(SourceRefusal::Read)
}

/// The 1-based first and last line of a unit's recorded span.
fn span_lines(line_start: i64, line_end: i64) -> Option<(usize, usize)> {
    let first = usize::try_from(line_start).ok()?;
    let last = usize::try_from(line_end).ok()?;
    Some((first.max(1), last))
}

/// A line's identifier tokens and the byte offset each starts at.
///
/// A token is `[A-Za-z0-9_$]+` that does not start with a digit.
fn identifiers(line: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut open: Option<usize> = None;
    for (at, c) in line.char_indices() {
        match open {
            None if is_ident_start(c) => open = Some(at),
            Some(from) if !is_ident_char(c) => {
                if let Some(token) = line.get(from..at) {
                    found.push((from, token));
                }
                open = None;
            }
            _ => {}
        }
    }
    if let Some(from) = open
        && let Some(token) = line.get(from..)
    {
        found.push((from, token));
    }
    found
}

/// Whether `qualified` is `old`, or ends in `::old` or `.old` (its final segment).
fn ends_in_segment(qualified: &str, old: &str) -> bool {
    qualified == old
        || qualified
            .strip_suffix(old)
            .is_some_and(|head| head.ends_with("::") || head.ends_with('.'))
}

/// `qualified` with its final segment replaced by `to`, keeping its separator.
fn splice_final_segment(qualified: &str, to: &str) -> String {
    if let Some((head, _)) = qualified.rsplit_once("::") {
        format!("{head}::{to}")
    } else if let Some((head, _)) = qualified.rsplit_once('.') {
        format!("{head}.{to}")
    } else {
        to.to_string()
    }
}

/// Every site a rename of `old` touches, reading each unit's file through the
/// root its tag names.
fn rename_symbol_plan(
    s: &Store,
    set: &RepoSet,
    old: &str,
    to: Option<&str>,
    preserves: &[String],
    map: Option<&str>,
) -> Result<RenamePlan> {
    // Compile user preserves + baked defaults
    let mut preserve_regexes = Vec::new();
    // Baked defaults: URL-ish (contains ://), kebab-case attrs
    preserve_regexes.push(Regex::new(r".*://.*")?);
    preserve_regexes.push(Regex::new(r"(?i)^[a-z]+(-[a-z]+)+$")?);
    for p in preserves {
        preserve_regexes.push(
            Regex::new(p).map_err(|e| anyhow::anyhow!("invalid --preserve regex {p:?}: {e}"))?,
        );
    }

    // Parse --map k=v,... longest-key-first
    let mut map_vec = Vec::new();
    if let Some(m) = map {
        for pair in m.split(',') {
            if let Some((k, v)) = pair.split_once('=') {
                map_vec.push((k.to_string(), v.to_string()));
            }
        }
        map_vec.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    }

    let mut sites = Vec::new();
    let mut unread = Vec::new();

    // 1. Symbol-table sites: units whose qualified ends with ::old or .old (final component)
    {
        let mut st = s.conn.prepare(
            "SELECT path, line_start, qualified FROM units WHERE qualified = ?1 OR qualified LIKE ?2 ESCAPE '\\' OR qualified LIKE ?3 ESCAPE '\\'",
        )?;
        let literal = like_literal(old);
        let rows = st.query_map(
            [old, &format!("%::{literal}"), &format!("%.{literal}")],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?;
        for r in rows {
            let (path, line, qualified) = r?;
            if !ends_in_segment(&qualified, old) {
                continue;
            }
            let replacement = to.map(|t| splice_final_segment(&qualified, t));
            sites.push(serde_json::json!({
                "kind": "symbol",
                "path": path,
                "line": line,
                "col": 0,
                "context": qualified,
                "replacement": replacement,
            }));
        }
    }

    // 2. Occurrence sites: scan unit source spans for whole-token matches
    // Load all units with their spans
    let units: Vec<(String, i64, i64)> = {
        let mut st = s
            .conn
            .prepare("SELECT path, line_start, line_end FROM units")?;
        st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<std::result::Result<_, _>>()?
    };

    // Cache file lines per path; a refused file is recorded once, as `None`.
    let mut line_cache: HashMap<String, Option<Vec<String>>> = HashMap::new();

    for (path, line_start, line_end) in units {
        if !line_cache.contains_key(&path) {
            let read = source_lines(set, &path);
            if let Err(why) = &read {
                unread.push(UnreadFile {
                    path: path.clone(),
                    why: why.clone(),
                });
            }
            line_cache.insert(path.clone(), read.ok());
        }
        let Some(Some(lines)) = line_cache.get(&path) else {
            continue;
        };
        let Some((first, last)) = span_lines(line_start, line_end) else {
            unread.push(UnreadFile {
                path,
                why: SourceRefusal::LineNumber,
            });
            continue;
        };
        // An empty span (the `file` unit of an empty file) holds no line.
        if last < first {
            continue;
        }
        if lines.len() < last {
            unread.push(UnreadFile {
                path,
                why: SourceRefusal::SpanPastFile {
                    line_start,
                    line_end,
                    lines: lines.len(),
                },
            });
            continue;
        }
        let count = last.saturating_sub(first).saturating_add(1);

        for (index, line) in lines
            .iter()
            .enumerate()
            .skip(first.saturating_sub(1))
            .take(count)
        {
            for (at, token) in identifiers(line) {
                if token != old || preserve_regexes.iter().any(|re| re.is_match(token)) {
                    continue;
                }
                let (Ok(line_no), Some(col)) = (
                    i64::try_from(index.saturating_add(1)),
                    i64::try_from(at).ok().and_then(|c| c.checked_add(1)),
                ) else {
                    unread.push(UnreadFile {
                        path: path.clone(),
                        why: SourceRefusal::LineNumber,
                    });
                    continue;
                };

                // Check map override
                let replacement = to.map(|t| {
                    map_vec
                        .iter()
                        .find(|(k, _)| k == token)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| t.to_string())
                });

                sites.push(serde_json::json!({
                    "kind": "occurrence",
                    "path": path,
                    "line": line_no,
                    "col": col,
                    "context": line.trim(),
                    "replacement": replacement,
                }));
            }
        }
    }

    // Deduplicate by (path, line, col, kind)
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for s in sites {
        let key = (
            s.get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            s.get("line").and_then(|v| v.as_i64()).unwrap_or(0),
            s.get("col").and_then(|v| v.as_i64()).unwrap_or(0),
            s.get("kind")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
        );
        if seen.insert(key) {
            deduped.push(s);
        }
    }
    let mut sites = deduped;

    // Sort for deterministic output
    sites.sort_by(|a, b| {
        let a_path = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let b_path = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
        let a_line = a.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
        let b_line = b.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
        let a_kind = a.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let b_kind = b.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        a_path
            .cmp(b_path)
            .then(a_line.cmp(&b_line))
            .then(a_kind.cmp(b_kind))
    });

    Ok(RenamePlan { sites, unread })
}

/// One JSON site per line on stdout.
fn write_sites(sites: &[serde_json::Value]) -> std::io::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    for site in sites {
        writeln!(out, "{site}")?;
    }
    Ok(())
}

/// `rename-symbol <old> [--to <new>] [--preserve <regex>...] [--map k=v,...]`:
/// finds resolved occurrences of a symbol name (units/links). Outputs JSON lines:
/// {kind,path,line,col,context,replacement?}. kind ∈ {symbol,occurrence}.
/// --preserve: user regexes + baked defaults (URL-ish, kebab-case attrs).
/// --map: k=v comma-separated, longest-key-first overrides correlated replacements.
///
/// Each unit's file is read through the root its tag names in the recorded
/// root set. A file that cannot be read is reported on stderr after the plan
/// is printed, and the command fails: a partial plan is never a complete one.
/// Read-only.
pub fn cmd_rename_symbol(
    db: &str,
    old: &str,
    to: Option<&str>,
    preserves: &[String],
    map: Option<&str>,
) -> Result<()> {
    let s = Store::open(db)?;
    let set = s.repo_set()?;
    let plan = rename_symbol_plan(&s, &set, old, to, preserves, map)?;
    if let Err(e) = write_sites(&plan.sites)
        && e.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(e.into());
    }
    if plan.unread.is_empty() {
        return Ok(());
    }
    for unread in &plan.unread {
        eprintln!(
            "ipe-index: not indexing {}: {}",
            shown(&unread.path),
            unread.why
        );
    }
    anyhow::bail!(
        "the rename plan is incomplete: {} file(s) were not read",
        plan.unread.len()
    )
}

fn is_ident_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lang;

    #[test]
    fn splice_path_preserves_tag_and_subtree() {
        assert_eq!(
            splice_path("ipe:tools/old", "tools/old", "tools/new"),
            "ipe:tools/new"
        );
        assert_eq!(
            splice_path("ipe:tools/old/src/a.rs", "tools/old", "tools/new"),
            "ipe:tools/new/src/a.rs"
        );
        // Untagged store still works.
        assert_eq!(splice_path("tools/old/x", "tools/old", "n"), "n/x");
    }

    #[test]
    fn path_patterns_cover_tagged_and_untagged() {
        let (e, et, s, st) = path_match_patterns("tools/x");
        assert_eq!(e, "tools/x");
        assert_eq!(et, "%:tools/x");
        assert_eq!(s, "tools/x/%");
        assert_eq!(st, "%:tools/x/%");
    }

    // A subtree matches whole dotted segments of the exact, case-sensitive
    // name, though the SQL `LIKE` selecting its rows ignores ASCII case.
    #[test]
    fn rdeps_subtree_is_case_sensitive_and_whole_segment() {
        let s = Store::open(":memory:").unwrap();
        for (src, dst) in [
            ("a.ipe", "Foo.Bar"),
            ("b.ipe", "foo.bar"),
            ("c.ipe", "Foo"),
            ("d.ipe", "FooX.Y"),
            ("e.ipe", "FOO.Bar"),
        ] {
            s.put_edge(src, dst, "import").unwrap();
        }
        let got: Vec<String> = rdeps_sources(&s, "Foo", true)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(got, ["a.ipe", "c.ipe"]);
        let exact: Vec<String> = rdeps_sources(&s, "Foo", false)
            .unwrap()
            .into_iter()
            .collect();
        assert_eq!(exact, ["c.ipe"]);
    }

    #[test]
    fn path_patterns_escape_the_typed_name() {
        let (e, et, s, st) = path_match_patterns("tools/x_y%");
        assert_eq!(e, "tools/x_y%");
        assert_eq!(et, "%:tools/x\\_y\\%");
        assert_eq!(s, "tools/x\\_y\\%/%");
        assert_eq!(st, "%:tools/x\\_y\\%/%");
    }

    // A small indexed store to exercise the review commands.
    fn seeded() -> Store {
        let s = Store::open(":memory:").unwrap();
        s.put_file("ipe:src/lib.rs", "rs", "compiler-rs", 0, "")
            .unwrap();
        crate::extract::extract_file(
            &s,
            "ipe:src/lib.rs",
            Lang::Rust,
            "pub fn caller() { helper(); }\npub fn helper() {}\n",
            "sha",
        )
        .unwrap();
        s
    }

    #[test]
    fn resolve_units_by_name_qualified_and_uid() {
        let s = seeded();
        let by_name = resolve_units(&s, "helper").unwrap();
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].qualified, "crate::helper");
        let by_qual = resolve_units(&s, "crate::helper").unwrap();
        assert_eq!(by_qual.len(), 1);
        let uid = by_name[0].uid.clone();
        let by_uid = resolve_units(&s, &uid).unwrap();
        assert_eq!(by_uid.len(), 1);
        assert_eq!(by_uid[0].uid, uid);
        assert!(resolve_units(&s, "nope").unwrap().is_empty());
    }

    #[test]
    fn callers_and_callees_traverse_the_callgraph() {
        let s = seeded();
        let helper = &resolve_units(&s, "helper").unwrap()[0];
        let caller = &resolve_units(&s, "caller").unwrap()[0];
        let n_callers: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM callgraph WHERE callee_uid=?1",
                [&helper.uid],
                |r| r.get(0),
            )
            .unwrap();
        let n_callees: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM callgraph WHERE caller_uid=?1",
                [&caller.uid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_callers, 1);
        assert_eq!(n_callees, 1);
    }

    #[test]
    fn like_literal_escapes_every_wildcard() {
        assert_eq!(like_literal("a_b%c\\d"), "a\\_b\\%c\\\\d");
        assert_eq!(like_literal("plain/path.rs"), "plain/path.rs");
    }

    // The escaped text matches itself and nothing a wildcard would widen to.
    #[test]
    fn like_literal_matches_only_itself_in_sql() {
        let s = Store::open(":memory:").unwrap();
        let matches = |text: &str, pattern: &str| -> bool {
            s.conn
                .query_row(
                    "SELECT ?1 LIKE ?2 ESCAPE '\\'",
                    rusqlite::params![text, pattern],
                    |r| r.get(0),
                )
                .unwrap()
        };
        let pattern = format!("%{}%", like_literal("a_b"));
        assert!(matches("xa_by", &pattern));
        assert!(!matches("xaxby", &pattern));
        let percent = format!("%{}%", like_literal("50%"));
        assert!(matches("is 50% done", &percent));
        assert!(!matches("is 500 done", &percent));
    }

    #[test]
    fn names_path_is_whole_segment_and_case_sensitive() {
        assert!(names_path("ipe:tools/x", "tools/x"));
        assert!(names_path("ipe:tools/x/y.rs", "tools/x"));
        assert!(names_path("tools/x", "tools/x"));
        assert!(!names_path("ipe:tools/xy", "tools/x"));
        assert!(!names_path("ipe:tools/X", "tools/x"));
        assert!(!names_path("ipe:other/tools/x", "tools/x"));
    }

    #[test]
    fn module_tails_are_dotted_suffixes_only() {
        assert_eq!(below_module("A.B", "A.B"), Some(""));
        assert_eq!(below_module("A.B.C", "A.B"), Some(".C"));
        assert_eq!(below_module("A.BC", "A.B"), None);
        assert_eq!(below_module("a.b", "A.B"), None);
        assert_eq!(edge_tail("X", Some("A.B"), "A.B"), Some(""));
        assert_eq!(edge_tail("A.B.C", None, "A.B"), Some(".C"));
        assert_eq!(edge_tail("X", Some("A.B.D"), "A.B"), Some(".D"));
        assert_eq!(edge_tail("X", Some("A.BD"), "A.B"), None);
    }

    #[test]
    fn identifiers_are_ascii_tokens_that_do_not_start_with_a_digit() {
        assert_eq!(
            identifiers("let 1ab = $x_y + é9z;"),
            vec![(5, "ab"), (10, "$x_y"), (20, "z")]
        );
        assert_eq!(identifiers("tail"), vec![(0, "tail")]);
        assert!(identifiers("  12 + 3 ").is_empty());
    }

    #[test]
    fn final_segment_matching_and_splicing() {
        assert!(ends_in_segment("crate::a::run", "run"));
        assert!(ends_in_segment("Mod.run", "run"));
        assert!(ends_in_segment("run", "run"));
        assert!(!ends_in_segment("crate::a::rerun", "run"));
        assert!(!ends_in_segment("crate::a::Run", "run"));
        assert_eq!(splice_final_segment("crate::a::run", "go"), "crate::a::go");
        assert_eq!(splice_final_segment("Mod.run", "go"), "Mod.go");
        assert_eq!(splice_final_segment("run", "go"), "go");
    }

    #[test]
    fn a_recorded_span_is_a_line_range_or_a_refusal() {
        assert_eq!(span_lines(3, 9), Some((3, 9)));
        assert_eq!(span_lines(0, 0), Some((1, 0)));
        assert_eq!(span_lines(-1, 4), None);
        assert_eq!(span_lines(1, -4), None);
    }

    // A tag the root set does not hold is a typed refusal, never a read at `.`.
    #[cfg(unix)]
    #[test]
    fn an_unknown_tag_is_refused_before_any_read() {
        use crate::walk::fixture::set;
        let roots = set(&[("ipe", ".")]);
        assert!(matches!(
            source_lines(&roots, "zzz:x.rs"),
            Err(SourceRefusal::Locate(LocateRefusal::UnknownTag { .. }))
        ));
        assert!(matches!(
            source_lines(&roots, "x.rs"),
            Err(SourceRefusal::Locate(LocateRefusal::UnknownTag { .. }))
        ));
        assert!(matches!(
            source_lines(&roots, "ipe:../x.rs"),
            Err(SourceRefusal::Locate(LocateRefusal::Path(_)))
        ));
    }

    /// Indexes the fixture as `out` with `sub` declared inside it as `in`.
    #[cfg(unix)]
    fn index_nested(fx: &crate::walk::fixture::Fixture, sub: &str) -> String {
        let db = fx.path(".git/ipe-index.db");
        let roots = [format!("out:{}", fx.root()), format!("in:{}", fx.path(sub))];
        crate::cmd_index(&roots, &db).unwrap();
        db
    }

    #[cfg(unix)]
    fn occurrences(plan: &RenamePlan) -> Vec<(String, i64)> {
        plan.sites
            .iter()
            .filter(|s| s["kind"] == "occurrence")
            .map(|s| {
                (
                    s["path"].as_str().unwrap_or_default().to_string(),
                    s["line"].as_i64().unwrap_or_default(),
                )
            })
            .collect()
    }

    // A unit tagged `in:x.rs` is read from the root `in` names, not from `./x.rs`.
    #[cfg(unix)]
    #[test]
    fn rename_symbol_reads_through_the_units_root() {
        let fx = crate::walk::fixture::Fixture::new("query-rename-root");
        fx.write(
            "sub/x.rs",
            "pub fn old_name() {}\npub fn caller() { old_name(); }\n",
        );
        fx.write("x.rs", "pub fn unrelated() {}\npub fn another() {}\n");
        fx.commit("one");
        let db = index_nested(&fx, "sub");
        let s = Store::open(&db).unwrap();
        let set = s.repo_set().unwrap();
        let plan = rename_symbol_plan(&s, &set, "old_name", Some("new_name"), &[], None).unwrap();
        assert_eq!(plan.unread, []);
        assert_eq!(
            occurrences(&plan),
            [("in:x.rs".to_string(), 1), ("in:x.rs".to_string(), 2)]
        );
    }

    // A refused read drops no file silently: the plan names it and the command fails.
    #[cfg(unix)]
    #[test]
    fn rename_symbol_refused_read_fails_the_plan() {
        let fx = crate::walk::fixture::Fixture::new("query-rename-refused");
        fx.write("sub/x.rs", "pub fn old_name() {}\n");
        fx.write("sub/y.rs", "pub fn other() {}\n");
        fx.write("top.rs", "pub fn old_name() {}\n");
        fx.commit("one");
        let db = index_nested(&fx, "sub");
        std::fs::remove_file(fx.path("sub/x.rs")).unwrap();
        std::os::unix::fs::symlink(fx.path("sub/y.rs"), fx.path("sub/x.rs")).unwrap();
        let s = Store::open(&db).unwrap();
        let set = s.repo_set().unwrap();
        let plan = rename_symbol_plan(&s, &set, "old_name", None, &[], None).unwrap();
        assert_eq!(plan.unread.len(), 1, "{:?}", plan.unread);
        assert_eq!(plan.unread[0].path, "in:x.rs");
        assert!(matches!(
            plan.unread[0].why,
            SourceRefusal::Read(ReadRefusal::NotRegular(_))
        ));
        assert_eq!(occurrences(&plan), [("out:top.rs".to_string(), 1)]);
        let failed = cmd_rename_symbol(&db, "old_name", None, &[], None);
        assert!(
            failed
                .as_ref()
                .is_err_and(|e| e.to_string().contains("incomplete")),
            "{failed:?}"
        );
    }

    // A file the index recorded but that is gone is a refusal too, not an empty file.
    #[cfg(unix)]
    #[test]
    fn rename_symbol_absent_file_fails_the_plan() {
        let fx = crate::walk::fixture::Fixture::new("query-rename-absent");
        fx.write("x.rs", "pub fn old_name() {}\n");
        fx.commit("one");
        let db = fx.path(".git/ipe-index.db");
        crate::cmd_index(&[format!("ipe:{}", fx.root())], &db).unwrap();
        std::fs::remove_file(fx.path("x.rs")).unwrap();
        let s = Store::open(&db).unwrap();
        let set = s.repo_set().unwrap();
        let plan = rename_symbol_plan(&s, &set, "old_name", None, &[], None).unwrap();
        assert!(
            plan.unread
                .iter()
                .any(|u| u.path == "ipe:x.rs" && u.why == SourceRefusal::Read(ReadRefusal::Absent)),
            "{:?}",
            plan.unread
        );
    }

    // A unit that starts past the end of its file is a stale index, never a clamped scan.
    #[cfg(unix)]
    #[test]
    fn rename_symbol_span_past_the_file_fails_the_plan() {
        let fx = crate::walk::fixture::Fixture::new("query-rename-stale");
        fx.write(
            "x.rs",
            "pub fn a() {}\npub fn old_name() {}\npub fn b() {}\n",
        );
        fx.commit("one");
        let db = fx.path(".git/ipe-index.db");
        crate::cmd_index(&[format!("ipe:{}", fx.root())], &db).unwrap();
        fx.write("x.rs", "pub fn a() {}\n");
        let s = Store::open(&db).unwrap();
        let set = s.repo_set().unwrap();
        let plan = rename_symbol_plan(&s, &set, "old_name", None, &[], None).unwrap();
        assert!(
            plan.unread
                .iter()
                .any(|u| matches!(u.why, SourceRefusal::SpanPastFile { .. })),
            "{:?}",
            plan.unread
        );
    }

    // A unit whose first line is still there but whose last line is not is
    // stale too: its scan is refused, never cut short at the end of the file.
    #[cfg(unix)]
    #[test]
    fn rename_symbol_span_ending_past_the_file_fails_the_plan() {
        let fx = crate::walk::fixture::Fixture::new("query-rename-shrunk");
        fx.write("x.rs", "pub fn a() {}\npub fn old_name() {\n}\n");
        fx.write("empty.rs", "");
        fx.commit("one");
        let db = fx.path(".git/ipe-index.db");
        crate::cmd_index(&[format!("ipe:{}", fx.root())], &db).unwrap();
        fx.write("x.rs", "pub fn a() {}\npub fn old_name() {\n");
        let s = Store::open(&db).unwrap();
        let set = s.repo_set().unwrap();
        let plan = rename_symbol_plan(&s, &set, "old_name", None, &[], None).unwrap();
        assert!(
            plan.unread.iter().any(|u| u.why
                == SourceRefusal::SpanPastFile {
                    line_start: 2,
                    line_end: 3,
                    lines: 2,
                }),
            "{:?}",
            plan.unread
        );
        // An unchanged empty file is read whole, not refused.
        assert!(
            plan.unread.iter().all(|u| u.path == "ipe:x.rs"),
            "{:?}",
            plan.unread
        );
    }

    #[cfg(unix)]
    fn unit_paths(units: &[UnitRow]) -> Vec<&str> {
        let mut paths: Vec<&str> = units.iter().map(|u| u.path.as_str()).collect();
        paths.sort_unstable();
        paths.dedup();
        paths
    }

    // Two independent roots hold an `a.rs`; a hunk in one lists that root's units only.
    #[cfg(unix)]
    #[test]
    fn changed_matches_only_the_owning_tag() {
        use crate::walk::fixture::Fixture;
        let out = Fixture::new("query-changed-out");
        let inn = Fixture::new("query-changed-in");
        for fx in [&out, &inn] {
            fx.write("a.rs", "pub fn f() {}\n");
            fx.commit("one");
        }
        inn.write("a.rs", "pub fn f() { let _x = 1; }\n");
        inn.commit("two");
        let db = out.path(".git/ipe-index.db");
        let roots = [format!("out:{}", out.root()), format!("in:{}", inn.root())];
        crate::cmd_index(&roots, &db).unwrap();
        let s = Store::open(&db).unwrap();
        let units = changed_units(&s, inn.root(), "HEAD~1..HEAD").unwrap();
        assert_eq!(unit_paths(&units), ["in:a.rs"]);
    }

    // `_` in a file name is a character, not a wildcard that reaches `axb.rs`.
    #[cfg(unix)]
    #[test]
    fn changed_like_wildcards_are_literal() {
        let fx = crate::walk::fixture::Fixture::new("query-changed-like");
        fx.write("a_b.rs", "pub fn f() {}\n");
        fx.write("axb.rs", "pub fn f() {}\n");
        fx.commit("one");
        fx.write("a_b.rs", "pub fn f() { let _x = 1; }\n");
        fx.commit("two");
        let db = fx.path(".git/ipe-index.db");
        crate::cmd_index(&[format!("ipe:{}", fx.root())], &db).unwrap();
        let s = Store::open(&db).unwrap();
        let units = changed_units(&s, fx.root(), "HEAD~1..HEAD").unwrap();
        assert_eq!(unit_paths(&units), ["ipe:a_b.rs"]);
    }

    // A root that is a subdirectory of its work tree is diffed by root-relative paths,
    // and a path under a root nested in the diffed root belongs to the nested tag.
    #[cfg(unix)]
    #[test]
    fn changed_subdir_root_is_diffed_relative() {
        let fx = crate::walk::fixture::Fixture::new("query-changed-sub");
        fx.write("sub/a.rs", "pub fn f() {}\n");
        fx.write("top.rs", "pub fn t() {}\n");
        fx.commit("one");
        fx.write("sub/a.rs", "pub fn f() { let _x = 1; }\n");
        fx.write("top.rs", "pub fn t() { let _y = 2; }\n");
        fx.commit("two");
        let db = index_nested(&fx, "sub");
        let s = Store::open(&db).unwrap();
        let inner = changed_units(&s, &fx.path("sub"), "HEAD~1..HEAD").unwrap();
        assert_eq!(unit_paths(&inner), ["in:a.rs"]);
        let outer = changed_units(&s, fx.root(), "HEAD~1..HEAD").unwrap();
        assert_eq!(unit_paths(&outer), ["in:a.rs", "out:top.rs"]);
    }

    // A directory that is none of the recorded roots is refused, never diffed.
    #[cfg(unix)]
    #[test]
    fn changed_refuses_a_dir_that_is_no_recorded_root() {
        use crate::walk::fixture::Fixture;
        let fx = Fixture::new("query-changed-root");
        fx.write("sub/a.rs", "pub fn f() {}\n");
        fx.commit("one");
        let other = Fixture::new("query-changed-other");
        other.write("a.rs", "pub fn f() {}\n");
        other.commit("one");
        let db = fx.path(".git/ipe-index.db");
        crate::cmd_index(&[format!("ipe:{}", fx.root())], &db).unwrap();
        let s = Store::open(&db).unwrap();
        for dir in [other.root().to_string(), fx.path("sub"), fx.path("nope")] {
            let err = changed_units(&s, &dir, "HEAD~1..HEAD").unwrap_err();
            assert!(
                err.downcast_ref::<ChangedRefusal>().is_some(),
                "{dir}: {err}"
            );
        }
    }

    // `_` and `%` in a path are literal, and a `LIKE` that folds case does not widen it.
    #[test]
    fn rename_path_like_wildcards_are_literal() {
        let s = Store::open(":memory:").unwrap();
        for path in [
            "ipe:a_b/x.rs",
            "ipe:axb/x.rs",
            "ipe:A_B/y.rs",
            "ipe:a%b/z.rs",
            "ipe:a_b",
        ] {
            s.put_file(path, "rs", "compiler-rs", 0, "").unwrap();
        }
        let paths = |old: &str| -> Vec<String> {
            rename_path_sites(&s, old, None)
                .unwrap()
                .iter()
                .map(|site| site["path"].as_str().unwrap_or_default().to_string())
                .collect()
        };
        assert_eq!(paths("a_b"), ["ipe:a_b", "ipe:a_b/x.rs"]);
        assert_eq!(paths("a%b"), ["ipe:a%b/z.rs"]);
        assert!(paths("a_").is_empty());
    }

    #[test]
    fn rename_path_replaces_through_the_tag() {
        let s = Store::open(":memory:").unwrap();
        s.put_file("ipe:tools/old/a.rs", "rs", "compiler-rs", 0, "")
            .unwrap();
        let sites = rename_path_sites(&s, "tools/old", Some("tools/new")).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0]["replacement"], "ipe:tools/new/a.rs");
    }
}

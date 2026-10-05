use crate::store::Store;
use anyhow::Result;
use regex::Regex;
use std::collections::{HashMap, HashSet};

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

/// `changed <git-range>`: the review entry point for a branch/PR. Lists the
/// units that fall inside the changed line ranges of `<range>` (e.g.
/// `main..HEAD`), each as a concise clickable coordinate, so a reviewer sees
/// exactly which symbols a diff touched — not just which files. Read-only.
pub fn cmd_changed(db: &str, repo: &str, range: &str) -> Result<()> {
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
    // The changed line ranges per file, from git — the source of truth for
    // which units a diff overlaps.
    let hunks = crate::diff::changed_line_ranges(repo, range)?;
    let mut any = false;
    let mut st = s.conn.prepare(
        "SELECT uid, path, kind, qualified, line_start, line_end, facing, purpose \
         FROM units WHERE (path = ?1 OR path LIKE ?2) AND kind != 'file' \
         ORDER BY line_start",
    )?;
    for (rel, ranges) in &hunks {
        // A unit is stored under a `tag:` prefix; match the untagged rel.
        let tagged = format!("%:{rel}");
        let rows: Vec<UnitRow> = st
            .query_map(rusqlite::params![rel, tagged], |r| {
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
        for u in &rows {
            if ranges
                .iter()
                .any(|(a, b)| u.line_start <= *b && *a <= u.line_end)
            {
                writeln_bp!("{}", unit_line(u));
                let _ = &u.facing;
                let _ = &u.purpose;
                any = true;
            }
        }
    }
    if !any {
        writeln_bp!("(no changed units in {range})");
    }
    Ok(())
}

pub fn cmd_rdeps(db: &str, module: &str, count: bool, subtree: bool) -> Result<()> {
    use std::io::Write;
    let s = Store::open(db)?;
    // Determine whether the arg looks like a file path (contains '/' or ends with a
    // file extension) so we can match on `resolved` instead of `dst`.
    let looks_like_path = module.contains('/') || module.contains('.');
    // Build the WHERE clause:
    //   - exact dst match (default): `dst = ?`
    //   - exact resolved match when arg is path-shaped: `resolved = ?`
    //   - subtree: additionally `dst LIKE 'module.%'`
    // We do NOT use unanchored LIKE so `rdeps "List"` can't accidentally
    // fold in `Data.List`, `container/list`, or `*ListSpec` files.
    if count {
        let n: i64 = if subtree {
            s.conn.query_row(
                "SELECT COUNT(DISTINCT src) FROM edges \
                 WHERE kind='import' AND (dst=?1 OR dst LIKE ?2 OR resolved=?1)",
                rusqlite::params![module, format!("{module}.%")],
                |r| r.get(0),
            )?
        } else if looks_like_path {
            s.conn.query_row(
                "SELECT COUNT(DISTINCT src) FROM edges \
                 WHERE kind='import' AND (dst=?1 OR resolved=?1)",
                rusqlite::params![module],
                |r| r.get(0),
            )?
        } else {
            s.conn.query_row(
                "SELECT COUNT(DISTINCT src) FROM edges \
                 WHERE kind='import' AND dst=?1",
                rusqlite::params![module],
                |r| r.get(0),
            )?
        };
        println!("{n}");
    } else {
        let stdout = std::io::stdout();
        let sql_and_params: (&str, Vec<String>);
        let (sql, params) = if subtree {
            sql_and_params = (
                "SELECT DISTINCT src FROM edges \
                 WHERE kind='import' AND (dst=?1 OR dst LIKE ?2 OR resolved=?1) ORDER BY src",
                vec![module.to_string(), format!("{module}.%")],
            );
            (&sql_and_params.0, &sql_and_params.1)
        } else if looks_like_path {
            sql_and_params = (
                "SELECT DISTINCT src FROM edges \
                 WHERE kind='import' AND (dst=?1 OR resolved=?1) ORDER BY src",
                vec![module.to_string()],
            );
            (&sql_and_params.0, &sql_and_params.1)
        } else {
            sql_and_params = (
                "SELECT DISTINCT src FROM edges \
                 WHERE kind='import' AND dst=?1 ORDER BY src",
                vec![module.to_string()],
            );
            (&sql_and_params.0, &sql_and_params.1)
        };
        let mut st = s.conn.prepare(sql)?;
        let rows = st.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            r.get::<_, String>(0)
        })?;
        let mut locked = stdout.lock();
        for r in rows {
            let src = r?;
            if let Err(e) = writeln!(locked, "{src}") {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    return Ok(());
                }
                return Err(e.into());
            }
        }
    }
    Ok(())
}

pub fn cmd_deps(db: &str, module: &str) -> Result<()> {
    let s = Store::open(db)?;
    // NOTE: deliberately unanchored substring match (the CLI documents `deps` as
    // "substring match"). `?1` is bound as a parameter, so this is injection-safe;
    // the looseness — `deps "List"` folding in any path containing "List" — is the
    // documented CLI contract, not a bug. Use `rdeps` for exact dst/resolved match.
    let mut st = s.conn.prepare(
        "SELECT DISTINCT dst FROM edges WHERE src LIKE ?1 AND kind='import' ORDER BY dst",
    )?;
    let rows = st.query_map([format!("%{module}%")], |r| r.get::<_, String>(0))?;
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
    let mut st = s
        .conn
        .prepare("SELECT src FROM edges WHERE kind='covers' AND dst LIKE ?1 ORDER BY src")?;
    let rows = st.query_map([format!("%{kernel}%")], |r| r.get::<_, String>(0))?;
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

/// Resolution pass: for every import edge, resolve `dst` to a canonical file
/// path within the repo, or to none. Writes `edges.resolved` in a single
/// transaction.
///
/// Every import edge is resolved again against the current `files`, not only
/// the unresolved ones: an incremental `update` that deletes or adds a file
/// can change what an unchanged file's import names, and the stored
/// resolution must be the one a fresh `index` computes. Only edges whose
/// resolution changed are written.
/// Bounded: loads tracked file paths into a `HashSet` (bounded by file count);
/// buffers the changed resolutions into a `Vec` (bounded by import-edge count)
/// because rusqlite does not permit a prepared SELECT and an `execute()` on
/// the same `Connection` at once.
pub fn resolve_edges(s: &Store, repo: &str) -> Result<()> {
    let mut known: HashSet<String> = HashSet::new();
    {
        let mut st = s.conn.prepare("SELECT path FROM files")?;
        for row in st.query_map([], |r| r.get::<_, String>(0))? {
            known.insert(row?);
        }
    }
    let to_update: Vec<(i64, Option<String>)> = {
        let mut st = s
            .conn
            .prepare("SELECT rowid, src, dst, resolved FROM edges WHERE kind='import'")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?;
        let mut changed = Vec::new();
        for row in rows {
            let (rowid, src, dst, stored) = row?;
            let resolved = resolve_import(&src, &dst, repo, &known);
            if resolved != stored {
                changed.push((rowid, resolved));
            }
        }
        changed
    };
    let write = |conn: &rusqlite::Connection| -> Result<()> {
        for (rowid, resolved) in &to_update {
            conn.execute(
                "UPDATE edges SET resolved=? WHERE rowid=?",
                rusqlite::params![resolved, rowid],
            )?;
        }
        Ok(())
    };
    // Inside the caller's transaction (`index`/`update`) write directly;
    // otherwise wrap the writes in one. The SELECT above is fully
    // materialised into `to_update` before any write, so no prepared
    // statement is live on `conn` during the UPDATEs.
    if s.conn.is_autocommit() {
        let tx = s.conn.unchecked_transaction()?;
        write(&tx)?;
        tx.commit()?;
    } else {
        write(&s.conn)?;
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

    // Find the crate root (directory containing Cargo.toml, inferred as parent
    // of `src/`) on the path below its repo tag, so a crate at the top of a
    // tagged root (`ipe:src/a.rs`) is found as `src`, then tag it back.
    let (tag, untagged) = crate::model::split_tag(src);
    let crate_root = find_crate_root(std::path::Path::new(untagged))?;
    let crate_root = if tag.is_empty() {
        crate_root
    } else {
        format!("{tag}:{crate_root}")
    };

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

/// A5 `links <uid>`: outgoing links and callgraph calls of one unit.
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

/// A5 `neighbors <uid>`: links + callgraph edges in BOTH directions around a
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

/// A6 `pending`: change-queue rows as JSON lines (one object per queued unit).
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

/// A7 `rename-path <old> [--to <new>]`: whole-segment path match across
/// files, symbols, units, import edges (dst/resolved), and links (to_ref).
/// Outputs JSON lines: {kind,path,line,col,context,replacement?}.
/// kind ∈ {file,symbol,unit,import,link}. Read-only.
/// Whole-segment path match for a stored (repo-tagged) path column. Stored
/// paths are `tag:rel`, but a caller types the untagged `rel`, so the four
/// patterns match the exact rel and its subtree under any tag prefix.
fn path_match_patterns(old: &str) -> (String, String, String, String) {
    (
        old.to_string(),      // exact, untagged (matches an untagged store)
        format!("%:{old}"),   // exact, under a `tag:` prefix
        format!("{old}/%"),   // subtree, untagged
        format!("%:{old}/%"), // subtree, under a `tag:` prefix
    )
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
        // No structural match on the rel (should not happen given the SQL
        // filter); leave it unchanged rather than corrupt the path.
        rel.to_string()
    };
    if tag.is_empty() {
        new_rel
    } else {
        format!("{tag}:{new_rel}")
    }
}

pub fn cmd_rename_path(db: &str, old: &str, to: Option<&str>) -> Result<()> {
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

    let mut sites = Vec::new();
    let (p_exact, p_exact_tag, p_sub, p_sub_tag) = path_match_patterns(old);

    // files.path — exact or subtree, tagged or not.
    {
        let mut st = s.conn.prepare(
            "SELECT path FROM files WHERE path = ?1 OR path LIKE ?2 OR path LIKE ?3 OR path LIKE ?4",
        )?;
        let rows = st.query_map(
            rusqlite::params![p_exact, p_exact_tag, p_sub, p_sub_tag],
            |r| r.get::<_, String>(0),
        )?;
        for r in rows {
            let path = r?;
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
            "SELECT file, line, col, name FROM symbols WHERE file = ?1 OR file LIKE ?2 OR file LIKE ?3 OR file LIKE ?4",
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
            "SELECT path, line_start, qualified FROM units WHERE path = ?1 OR path LIKE ?2 OR path LIKE ?3 OR path LIKE ?4",
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

    // import edges: dst == old OR resolved == old OR dst LIKE old + '.%' OR resolved LIKE old + '.%'
    {
        let mut st = s.conn.prepare(
            "SELECT src, dst, resolved FROM edges WHERE kind='import' AND (dst = ?1 OR resolved = ?1 OR dst LIKE ?2 OR resolved LIKE ?2)",
        )?;
        let rows = st.query_map([old, &format!("{old}.%")], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        for r in rows {
            let (src, dst, resolved) = r?;
            let hit = if dst == old || resolved.as_deref() == Some(old) {
                old
            } else if dst.starts_with(&format!("{old}.")) {
                &dst
            } else {
                &resolved.unwrap_or_default()
            };
            let replacement = to.map(|t| {
                if hit == old {
                    t.to_string()
                } else {
                    format!("{t}{}", &hit[old.len()..])
                }
            });
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

    // links.to_ref == old OR LIKE old + '.%' (join units for path/line)
    {
        let mut st = s.conn.prepare(
            "SELECT l.to_ref, u.path, l.line FROM links l JOIN units u ON u.uid = l.from_uid WHERE l.to_ref = ?1 OR l.to_ref LIKE ?2",
        )?;
        let rows = st.query_map([old, &format!("{old}.%")], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        for r in rows {
            let (to_ref, path, line) = r?;
            let replacement = to.map(|t| {
                if to_ref == old {
                    t.to_string()
                } else {
                    format!("{t}{}", &to_ref[old.len()..])
                }
            });
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

    for site in sites {
        writeln_bp!("{}", serde_json::to_string(&site)?);
    }
    Ok(())
}

/// A8 `rename-symbol <old> [--to <new>] [--preserve <regex>...] [--map k=v,...]`:
/// finds resolved occurrences of a symbol name (units/links). Outputs JSON lines:
/// {kind,path,line,col,context,replacement?}. kind ∈ {symbol,occurrence}.
/// --preserve: user regexes + baked defaults (URL-ish, kebab-case attrs).
/// --map: k=v comma-separated, longest-key-first overrides correlated replacements.
/// Read-only.
pub fn cmd_rename_symbol(
    db: &str,
    old: &str,
    to: Option<&str>,
    preserves: &[String],
    map: Option<&str>,
) -> Result<()> {
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

    // 1. Symbol-table sites: units whose qualified ends with ::old or .old (final component)
    {
        let mut st = s.conn.prepare(
            "SELECT path, line_start, qualified FROM units WHERE qualified = ?1 OR qualified LIKE ?2 OR qualified LIKE ?3",
        )?;
        let rows = st.query_map([old, &format!("%::{old}"), &format!("%.{old}")], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for r in rows {
            let (path, line, qualified) = r?;
            let replacement = to.map(|t| {
                // Replace final segment — detect separator (:: or .) and splice correctly
                if let Some(idx) = qualified.rfind("::") {
                    format!("{}{t}", &qualified[..idx + 2])
                } else if let Some(idx) = qualified.rfind('.') {
                    format!("{}{t}", &qualified[..idx + 1])
                } else {
                    t.to_string()
                }
            });
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
    let units: Vec<(String, String, i64, i64, String)> = {
        let mut st = s
            .conn
            .prepare("SELECT uid, path, line_start, line_end, qualified FROM units")?;
        st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<_, _>>()?
    };

    // Cache file lines per path
    let mut line_cache: HashMap<String, Vec<String>> = HashMap::new();

    for (_uid, path, line_start, line_end, _qualified) in units {
        // Read file lines (tagged path: tag:rel)
        if !line_cache.contains_key(&path) {
            // Strip the repo tag the same way every other path consumer does,
            // then read the file relative to the repo root. A single repo is
            // indexed today, so the root is the current directory.
            let (_tag, rel) = crate::model::split_tag(&path);
            let content =
                crate::walk::read_indexed(std::path::Path::new("."), rel).unwrap_or_default();
            let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
            line_cache.insert(path.clone(), lines);
        }
        let Some(lines) = line_cache.get(&path) else {
            continue;
        };

        // Clamp span to file bounds
        if lines.is_empty() {
            continue;
        }
        let start = (line_start as usize).max(1).min(lines.len());
        let end = (line_end as usize).max(start).min(lines.len());

        for line_no in start..=end {
            let line = &lines[line_no - 1];
            // Simple whole-token scan for `old`
            // Token = [A-Za-z0-9_$]+
            let mut col = 0usize;
            let bytes = line.as_bytes();
            while col < bytes.len() {
                // Skip non-ident chars
                while col < bytes.len() && !is_ident_start(bytes[col]) {
                    col += 1;
                }
                if col >= bytes.len() {
                    break;
                }
                let token_start = col;
                while col < bytes.len() && is_ident_char(bytes[col]) {
                    col += 1;
                }
                let token = &line[token_start..col];
                if token == old {
                    // Check preserves
                    let mut skip = false;
                    for re in &preserve_regexes {
                        if re.is_match(token) {
                            skip = true;
                            break;
                        }
                    }
                    if skip {
                        continue;
                    }

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
                        "line": line_no as i64,
                        "col": token_start as i64 + 1,
                        "context": line.trim(),
                        "replacement": replacement,
                    }));
                }
            }
        }
    }

    // Deduplicate by (path, line, col, kind)
    use std::collections::HashSet;
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

    for site in sites {
        writeln_bp!("{}", serde_json::to_string(&site)?);
    }
    Ok(())
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b == b'$'
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Lang;

    // A `crate::` import resolves under the file's own crate root, found below
    // the repo tag: a crate at the top of a tagged root is `<tag>:src`, and a
    // nested crate keeps its directory.
    #[test]
    fn rust_import_resolves_under_a_tagged_crate_root() {
        let known: HashSet<String> = ["ipe:src/b.rs", "ipe:tools/x/src/c.rs", "src/d.rs"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            resolve_rust_import("ipe:src/a.rs", "crate::b", &known).as_deref(),
            Some("ipe:src/b.rs")
        );
        assert_eq!(
            resolve_rust_import("ipe:tools/x/src/a.rs", "crate::c", &known).as_deref(),
            Some("ipe:tools/x/src/c.rs")
        );
        assert_eq!(
            resolve_rust_import("src/a.rs", "crate::d", &known).as_deref(),
            Some("src/d.rs")
        );
        assert_eq!(
            resolve_rust_import("ipe:src/a.rs", "crate::d", &known),
            None
        );
    }

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

    // A small indexed store to exercise the review commands.
    fn seeded() -> Store {
        let s = Store::open(":memory:").unwrap();
        s.put_file(
            "ipe:src/lib.rs",
            "rs",
            "compiler-rs",
            0,
            &crate::store::FileStamp::of_bytes(b""),
        )
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
}

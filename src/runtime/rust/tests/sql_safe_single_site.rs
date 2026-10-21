//! SQL-vouching inventory: the runtime asserts that run-time SQL text is safe at
//! exactly one admitted site.
//!
//! sqlx runs only `&'static str` text unasked; any other string reaches a query
//! through a vouch — `sqlx::AssertSqlSafe`, an `impl` of `sqlx::SqlSafeStr`, a
//! `sqlx::QueryBuilder` (which vouches for its pushed text inside sqlx) or a
//! hand-built `sqlx::SqlStr`. The runtime vouches only in `src/sql_text.rs`, whose entry points name where
//! their text comes from, so the scan counts, per file, every mention of each
//! vouching name and asserts the counts equal [`ADMITTED`]. A new site, a
//! dropped one, or one moved out of `sql_text.rs` turns the scan red.
//!
//! Every `.rs` file under `src/` is lexed by `proc_macro2`, the Rust lexer, so
//! comments and string literals are never code and a macro body is scanned like
//! any other tokens. A `use` alias, a group import and a fully qualified path
//! all still mention the name they rename, so each counts. No `#[cfg(test)]` is
//! honoured: test code in `src/` vouches nowhere either. A file another file
//! `include!`s from outside `src/` is scanned under its including file.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The names through which a non-literal string becomes sqlx query text.
const VOUCHING_NAMES: &[&str] = &["AssertSqlSafe", "SqlSafeStr", "SqlStr", "QueryBuilder"];

/// Every admitted mention: file, vouching name, count.
const ADMITTED: &[(&str, &str, usize)] = &[
    // The one construction of the driver's trust assertion.
    ("sql_text.rs", "AssertSqlSafe", 1),
    // The return types of `assembled`, `program_authored` and `vouch`.
    ("sql_text.rs", "SqlSafeStr", 3),
];

/// The most `include!` hops the scan follows from one file.
const MAX_INCLUDE_DEPTH: usize = 4;

/// Counts every vouching-name identifier in `tokens` into `counts` under
/// `file`, and returns the string paths of the `include!`s it saw.
fn count_tokens(
    tokens: TokenStream,
    file: &str,
    counts: &mut BTreeMap<(String, String), usize>,
    includes: &mut Vec<String>,
) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => count_tokens(group.stream(), file, counts, includes),
            TokenTree::Ident(id) => {
                let name = id.unraw().to_string();
                if VOUCHING_NAMES.contains(&name.as_str()) {
                    let count = counts.entry((file.to_owned(), name.clone())).or_insert(0);
                    *count = count.saturating_add(1);
                }
                let bang = matches!(
                    trees.get(at.saturating_add(1)),
                    Some(TokenTree::Punct(p)) if p.as_char() == '!'
                );
                if name == "include" && bang {
                    if let Some(TokenTree::Group(args)) = trees.get(at.saturating_add(2)) {
                        includes.extend(args.stream().into_iter().filter_map(|t| match t {
                            TokenTree::Literal(lit) => {
                                let text = lit.to_string();
                                text.strip_prefix('"')
                                    .and_then(|s| s.strip_suffix('"'))
                                    .map(str::to_owned)
                            }
                            _ => None,
                        }));
                    }
                }
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Every vouching-name mention in `sources`, keyed by file and name.
///
/// `read_outside` returns the text of an `include!`d path that lies outside
/// the walked sources, given the including file's name and the literal path.
fn vouch_sites(
    sources: &[(String, String)],
    read_outside: impl Fn(&str, &str) -> Result<String, String>,
) -> Result<BTreeMap<(String, String), usize>, String> {
    let mut counts = BTreeMap::new();
    for (name, text) in sources {
        let mut pending: Vec<(String, usize)> = Vec::new();
        let tokens =
            TokenStream::from_str(text).map_err(|e| format!("{name}: does not lex: {e}"))?;
        let mut includes = Vec::new();
        count_tokens(tokens, name, &mut counts, &mut includes);
        pending.extend(includes.into_iter().map(|path| (path, 1)));
        while let Some((path, depth)) = pending.pop() {
            if depth > MAX_INCLUDE_DEPTH {
                return Err(format!(
                    "{name}: `include!` nested deeper than {MAX_INCLUDE_DEPTH}"
                ));
            }
            let base = Path::new(name).parent().unwrap_or_else(|| Path::new(""));
            let joined = base.join(&path).to_string_lossy().replace('\\', "/");
            if sources.iter().any(|(other, _)| *other == joined) {
                continue;
            }
            let included = read_outside(name, &path)?;
            let tokens = TokenStream::from_str(&included)
                .map_err(|e| format!("{name}: `include!(\"{path}\")` does not lex: {e}"))?;
            let mut nested = Vec::new();
            count_tokens(tokens, name, &mut counts, &mut nested);
            pending.extend(nested.into_iter().map(|p| (p, depth.saturating_add(1))));
        }
    }
    Ok(counts)
}

/// Every difference between `sites` and [`ADMITTED`], one line each.
fn violations(sites: &BTreeMap<(String, String), usize>) -> Vec<String> {
    let mut out = Vec::new();
    for ((file, name), count) in sites {
        let admitted = ADMITTED
            .iter()
            .find(|(f, n, _)| f == file && n == name)
            .map_or(0, |(_, _, c)| *c);
        if *count != admitted {
            out.push(format!(
                "{file}: `{name}` mentioned {count} time(s), admitted {admitted}"
            ));
        }
    }
    for (file, name, count) in ADMITTED {
        if !sites.contains_key(&((*file).to_owned(), (*name).to_owned())) {
            out.push(format!(
                "{file}: `{name}` admitted {count} time(s), mentioned 0 (stale entry)"
            ));
        }
    }
    out
}

/// The real tree plus `extra`, scanned with no outside reader.
fn scan_with(extra: &[(&str, &str)]) -> Vec<String> {
    let mut sources = runtime_sources();
    sources.extend(
        extra
            .iter()
            .map(|(n, t)| ((*n).to_owned(), (*t).to_owned())),
    );
    match vouch_sites(&sources, read_from_src) {
        Ok(sites) => violations(&sites),
        Err(e) => vec![e],
    }
}

fn src_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn runtime_sources() -> Vec<(String, String)> {
    rust_sources(&src_root())
}

fn read_from_src(including: &str, path: &str) -> Result<String, String> {
    let file = src_root().join(including);
    let dir = file.parent().unwrap_or_else(|| Path::new(""));
    std::fs::read_to_string(dir.join(path))
        .map_err(|e| format!("{including}: `include!(\"{path}\")` unreadable: {e}"))
}

#[test]
fn runtime_vouches_for_sql_text_only_in_sql_text_rs() {
    let found = scan_with(&[]);
    assert!(
        found.is_empty(),
        "SQL-vouching sites differ:\n{}",
        found.join("\n")
    );
}

/// Each evasion shape outside `sql_text.rs`, each of which must turn the scan red.
const EVASIONS: &[(&str, &str)] = &[
    (
        "direct",
        "fn f(s: String) { let _ = sqlx::query(sqlx::AssertSqlSafe(s)); }",
    ),
    ("alias", "use sqlx::AssertSqlSafe as Trusted;"),
    ("group import", "use sqlx::{query, AssertSqlSafe};"),
    (
        "qualified path",
        "fn f(s: String) { let _ = sqlx_core::sql_str::AssertSqlSafe(s); }",
    ),
    (
        "raw identifier",
        "fn f(s: String) { let _ = sqlx::r#AssertSqlSafe(s); }",
    ),
    ("inside a macro", "m! { sqlx::AssertSqlSafe(s) }"),
    (
        "own trait impl",
        "impl sqlx::SqlSafeStr for Mine { fn into_sql_str(self) -> X { todo() } }",
    ),
    (
        "query builder",
        "fn f() { let _ = sqlx::QueryBuilder::<sqlx::Sqlite>::new(s); }",
    ),
    (
        "glob-imported builder",
        "use sqlx::*; fn f() { let _ = QueryBuilder::<Sqlite>::new(s); }",
    ),
    ("hand-built SqlStr", "fn f() -> sqlx::SqlStr { make() }"),
];

#[test]
fn every_evasion_shape_is_refused() {
    for (shape, text) in EVASIONS {
        let found = scan_with(&[("evasion.rs", text)]);
        assert!(
            found.iter().any(|line| line.starts_with("evasion.rs:")),
            "{shape}: not refused: {text}"
        );
    }
}

#[test]
fn a_second_vouch_inside_sql_text_rs_is_refused() {
    let mut sources = runtime_sources();
    let extra = "fn more(s: String) { let _ = sqlx::AssertSqlSafe(s); }";
    #[allow(clippy::expect_used)] // the admitted file missing must fail the test
    let (_, text) = sources
        .iter_mut()
        .find(|(n, _)| n == "sql_text.rs")
        .expect("sql_text.rs under src/");
    text.push_str(extra);
    let found = match vouch_sites(&sources, read_from_src) {
        Ok(sites) => violations(&sites),
        Err(e) => vec![e],
    };
    assert!(
        found
            .iter()
            .any(|line| line.starts_with("sql_text.rs: `AssertSqlSafe`")),
        "a second construction in sql_text.rs passed: {found:?}"
    );
}

#[test]
fn mentions_in_comments_and_strings_are_not_code() {
    let found = scan_with(&[(
        "prose.rs",
        "// sqlx::AssertSqlSafe\n/// `SqlSafeStr`\nconst S: &str = \"AssertSqlSafe QueryBuilder\";",
    )]);
    assert!(found.is_empty(), "prose counted as code: {found:?}");
}

#[test]
fn an_included_file_outside_src_is_scanned() {
    let sources = vec![(
        "host.rs".to_owned(),
        "include!(\"../elsewhere.rs\");".to_owned(),
    )];
    let outside = |_: &str, _: &str| Ok("fn f(s: String) { sqlx::AssertSqlSafe(s); }".to_owned());
    let found = match vouch_sites(&sources, outside) {
        Ok(sites) => violations(&sites),
        Err(e) => vec![e],
    };
    assert!(
        found
            .iter()
            .any(|line| line.starts_with("host.rs: `AssertSqlSafe`")),
        "an included vouch passed: {found:?}"
    );
}

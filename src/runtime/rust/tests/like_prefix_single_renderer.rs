//! One `LIKE` renderer: a literal prefix reaches SQL only through `LikePrefix`.
//!
//! The runtime renders every `LIKE` predicate in exactly one place,
//! `db::like_escape_sql` (`<subject> LIKE ? ESCAPE '\'`), and a literal prefix
//! reaches it only as an escaped `LikePrefix` pattern. `Sql.startsWith` and
//! `Store.startsWith` share that path: the stdlib renders a `StartsWith` leaf
//! through `Sql.startsWith`, never through `Sql.like` with a pattern it built
//! itself, and no stdlib string carries SQL `LIKE` text.
//!
//! The runtime half parses every `.rs` file under `src/` with `syn` and records
//! each production string literal (macro bodies included) that renders a SQL
//! `LIKE`; doc comments, comments and test-only code are not production
//! literals. A file reached only through an out-of-line `#[cfg(test)] mod` is
//! dropped; a module path the resolver does not model keeps its file scanned,
//! so a gap in the resolver turns the scan red, never vacuously green.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ImplItem, ImplItemFn, Item, ItemFn, LitStr, Macro, Meta, Stmt, TraitItem,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The one runtime function that renders SQL `LIKE` text.
const THE_RENDERER: (&str, &str) = ("db.rs", "like_escape_sql");

/// The most directory entries the stdlib walk reads before it fails.
const MAX_STDLIB_ENTRIES: usize = 4096;

/// Whether `text` renders a SQL `LIKE` / `ILIKE` predicate: the keyword in
/// capitals, or in any case when an operand (`?`, `$n`, a quoted literal, a
/// format hole or a parenthesis) follows it.
fn renders_sql_like(text: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut rest = text;
    while let Some(start) = rest.find(is_word) {
        let tail = rest.get(start..).unwrap_or_default();
        let end = tail.find(|c: char| !is_word(c)).unwrap_or(tail.len());
        let (word, after) = tail.split_at(end);
        let keyword = word.eq_ignore_ascii_case("like") || word.eq_ignore_ascii_case("ilike");
        let capitals = word == "LIKE" || word == "ILIKE";
        let operand = after.trim_start().starts_with(['?', '$', '\'', '{', '(']);
        if keyword && (capitals || operand) {
            return true;
        }
        rest = after;
    }
    false
}

/// One file's production `LIKE` renderings and its out-of-line test-only
/// modules.
#[derive(Default)]
struct Scan {
    fn_stack: Vec<String>,
    /// The enclosing function of each production literal that renders `LIKE`.
    renders: Vec<String>,
    /// `(module name, #[path] value)` of each out-of-line `#[cfg(test)] mod`.
    test_mods: Vec<(String, Option<String>)>,
}

impl Scan {
    fn record(&mut self) {
        let site = self
            .fn_stack
            .last()
            .map_or_else(|| "<item>".to_owned(), Clone::clone);
        self.renders.push(site);
    }

    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Literal(lit) => {
                    if renders_sql_like(&lit.to_string()) {
                        self.record();
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

/// The `#[path = "…"]` value among `attrs`, if any.
fn path_attr(attrs: &[Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if let Meta::NameValue(nv) = &attr.meta
            && nv.path.is_ident("path")
            && let Expr::Lit(lit) = &nv.value
            && let syn::Lit::Str(value) = &lit.lit
        {
            Some(value.value())
        } else {
            None
        }
    })
}

impl<'ast> Visit<'ast> for Scan {
    // Doc comments and `cfg` predicates are attributes, never rendered SQL.
    fn visit_attribute(&mut self, _attr: &'ast Attribute) {}

    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            if let Item::Mod(module) = item
                && module.content.is_none()
            {
                self.test_mods
                    .push((module.ident.to_string(), path_attr(&module.attrs)));
            }
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.fn_stack.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.fn_stack.pop();
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if cfg_test_only(impl_item_attrs(item)) {
            return;
        }
        if let ImplItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.fn_stack.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.fn_stack.pop();
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if cfg_test_only(trait_item_attrs(item)) {
            return;
        }
        if let TraitItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        let attrs: &[Attribute] = match stmt {
            Stmt::Local(local) => &local.attrs,
            Stmt::Macro(mac) => &mac.attrs,
            Stmt::Item(_) | Stmt::Expr(..) => &[],
        };
        if !cfg_test_only(attrs) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if cfg_test_only(expr_attrs(expr)) {
            return;
        }
        if let Expr::Verbatim(tokens) = expr {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_expr(self, expr);
    }

    fn visit_lit_str(&mut self, lit: &'ast LitStr) {
        if renders_sql_like(&lit.value()) {
            self.record();
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Scans one source; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its LIKE renderings cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan
}

fn join(dir: &str, rel: &str) -> String {
    if dir.is_empty() {
        rel.to_owned()
    } else {
        format!("{dir}/{rel}")
    }
}

/// The files an out-of-line `mod name;` declared in `parent` may load.
fn child_files(parent: &str, name: &str, path: Option<&str>) -> Vec<String> {
    let (dir, file) = parent.rsplit_once('/').unwrap_or(("", parent));
    if let Some(path) = path {
        return vec![join(dir, path)];
    }
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let base = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_owned()
    } else {
        join(dir, stem)
    };
    vec![
        join(&base, &format!("{name}.rs")),
        join(&base, &format!("{name}/mod.rs")),
    ]
}

/// Every production `LIKE` rendering across `sources`, as `(file, fn)`.
fn renderings(sources: &[(String, String)]) -> Vec<(String, String)> {
    let scans: Vec<(&str, Scan)> = sources
        .iter()
        .map(|(name, src)| (name.as_str(), scan(name, src)))
        .collect();
    let test_only: BTreeSet<String> = scans
        .iter()
        .flat_map(|(name, scan)| {
            scan.test_mods
                .iter()
                .flat_map(|(module, path)| child_files(name, module, path.as_deref()))
        })
        .collect();
    scans
        .into_iter()
        .filter(|(name, _)| !test_only.contains(*name))
        .flat_map(|(name, scan)| {
            scan.renders
                .into_iter()
                .map(move |site| (name.to_owned(), site))
        })
        .collect()
}

fn fixture(src: &str) -> Vec<String> {
    scan("fixture", src).renders
}

// ---------------------------------------------------------------------------
// Refusals: each second renderer the runtime scan must catch.
// ---------------------------------------------------------------------------

#[test]
fn a_second_formatted_like_renderer_is_caught() {
    let src = r#"fn second(s: &str) -> String { format!("{s} LIKE ? ESCAPE '!'") }"#;
    assert_eq!(fixture(src), vec!["second"]);
}

#[test]
fn a_lowercase_or_ilike_renderer_is_caught() {
    let src = r#"
fn lower() -> &'static str { "name like ?" }
struct S;
impl S {
    fn pg(&self) -> &'static str { "name ILIKE $1" }
}
"#;
    assert_eq!(fixture(src), vec!["lower", "pg"]);
}

#[test]
fn a_renderer_after_a_test_module_is_caught() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn t() -> &'static str { "n LIKE ? ESCAPE '\\'" }
}
fn after() -> String { String::from("(n LIKE ?)") }
"#;
    assert_eq!(fixture(src), vec!["after"]);
}

// ---------------------------------------------------------------------------
// Admitting controls: text that names `like` without rendering it.
// ---------------------------------------------------------------------------

#[test]
fn prose_messages_and_test_code_are_not_renderings() {
    let src = r#"
/// Renders `n LIKE ? ESCAPE '\'`.
fn production(kind: &str) -> String {
    // n LIKE ?
    let _ = "unlike ? and likely (so)";
    format!("Sql.like: the pattern {kind} is refused")
}
#[cfg(all(test, feature = "db"))]
mod db_tests;
"#;
    let scanned = scan("fixture", src);
    assert_eq!(scanned.renders, Vec::<String>::new());
    assert_eq!(scanned.test_mods, vec![("db_tests".to_owned(), None)]);
}

#[test]
fn an_out_of_line_test_module_resolves_beside_its_parent() {
    assert_eq!(
        child_files("mod.rs", "config_postgres_test", None),
        vec!["config_postgres_test.rs", "config_postgres_test/mod.rs"]
    );
    assert_eq!(
        child_files("web/server.rs", "t", None),
        vec!["web/server/t.rs", "web/server/t/mod.rs"]
    );
    assert_eq!(
        child_files("web/mod.rs", "t", Some("t_tests.rs")),
        vec!["web/t_tests.rs"]
    );
}

#[test]
fn a_test_only_file_is_dropped_and_a_production_file_is_kept() {
    let sources = [
        (
            "mod.rs".to_owned(),
            "#[cfg(test)]\nmod pg_test;\nmod live;\n".to_owned(),
        ),
        (
            "pg_test.rs".to_owned(),
            r#"fn t() -> &'static str { "n LIKE $1" }"#.to_owned(),
        ),
        (
            "live.rs".to_owned(),
            r#"fn r() -> &'static str { "n LIKE ?" }"#.to_owned(),
        ),
    ];
    assert_eq!(
        renderings(&sources),
        vec![("live.rs".to_owned(), "r".to_owned())]
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = fixture("fn production( { \"n LIKE ?\" }");
}

// ---------------------------------------------------------------------------
// The stdlib half: `StartsWith` renders through `Sql.startsWith`, and no
// stdlib string carries SQL `LIKE` text.
// ---------------------------------------------------------------------------

/// The string literals on the code part of each line of `src` (a `--`
/// comment, whole-line or trailing, is not code).
fn ipe_string_literals(src: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in src.lines() {
        let mut chars = line.chars().peekable();
        let mut text = String::new();
        let mut in_string = false;
        let mut escaped = false;
        while let Some(c) = chars.next() {
            if !in_string {
                if c == '"' {
                    in_string = true;
                } else if c == '-' && chars.peek() == Some(&'-') {
                    break;
                }
            } else if escaped {
                text.push(c);
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                found.push(std::mem::take(&mut text));
                in_string = false;
            } else {
                text.push(c);
            }
        }
    }
    found
}

/// The first non-blank line after each `StartsWith … ->` case arm in `src`.
fn starts_with_arm_bodies(src: &str) -> Vec<&str> {
    let mut lines = src.lines();
    let mut bodies = Vec::new();
    while let Some(line) = lines.next() {
        let arm = line.trim();
        if arm.starts_with("StartsWith ")
            && arm.ends_with("->")
            && let Some(body) = lines.by_ref().map(str::trim).find(|l| !l.is_empty())
        {
            bodies.push(body);
        }
    }
    bodies
}

/// The `StartsWith` arm bodies of `src` that render SQL, and those among them
/// that bypass `Sql.startsWith`.
fn starts_with_renderings(src: &str) -> (Vec<&str>, Vec<&str>) {
    let rendering: Vec<&str> = starts_with_arm_bodies(src)
        .into_iter()
        .filter(|body| body.contains("Sql."))
        .collect();
    let bypassing = rendering
        .iter()
        .copied()
        .filter(|body| !body.contains("Sql.startsWith") || body.contains("Sql.like"))
        .collect();
    (rendering, bypassing)
}

#[allow(clippy::expect_used)] // an unreadable stdlib source must fail the scan, never be skipped
fn ipe_sources(root: &Path) -> Vec<(String, String)> {
    let mut dirs: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    let mut entries = 0usize;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a stdlib directory") {
            let entry = entry.expect("read a stdlib directory entry");
            entries = entries.saturating_add(1);
            assert!(
                entries <= MAX_STDLIB_ENTRIES,
                "more than {MAX_STDLIB_ENTRIES} entries under {}",
                root.display()
            );
            let kind = entry.file_type().expect("read a stdlib entry's type");
            let path = entry.path();
            assert!(
                !kind.is_symlink(),
                "{}: a symbolic link in the stdlib is not scanned",
                path.display()
            );
            if kind.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "ipe") {
                let text = std::fs::read_to_string(&path).expect("read a stdlib source");
                sources.push((path.display().to_string(), text));
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn a_starts_with_arm_rendered_through_like_is_caught() {
    let src = r#"
        StartsWith col prefix ->
            Result.map (\live -> Sql.like (Sql.column live) (escape prefix)) (liveName view col)

        StartsWith col prefix ->
            Result.map (\live -> Sql.startsWith (Sql.column live) prefix) (liveName view col)

        StartsWith col prefix ->
            StartsWith col prefix
"#;
    let (rendering, bypassing) = starts_with_renderings(src);
    assert_eq!(rendering.len(), 2);
    assert_eq!(
        bypassing,
        vec![
            r"Result.map (\live -> Sql.like (Sql.column live) (escape prefix)) (liveName view col)"
        ]
    );
}

#[test]
fn a_like_string_is_caught_and_a_comment_is_not() {
    let src = r#"
-- Sql.raw "n LIKE ?"
frag = Sql.raw "n LIKE ? ESCAPE '\\'" -- "n LIKE ?"
label = "like a charm"
"#;
    let literals = ipe_string_literals(src);
    assert_eq!(literals, vec![r"n LIKE ? ESCAPE '\'", "like a charm"]);
    let rendering: Vec<&String> = literals.iter().filter(|s| renders_sql_like(s)).collect();
    assert_eq!(rendering, vec![r"n LIKE ? ESCAPE '\'"]);
}

// ---------------------------------------------------------------------------
// The scans over the real trees.
// ---------------------------------------------------------------------------

/// Every production `LIKE` the runtime renders comes from `like_escape_sql`.
#[test]
fn the_runtime_renders_like_in_one_place() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    assert!(
        sources.iter().any(|(name, _)| name == THE_RENDERER.0),
        "the source walk did not read {}",
        THE_RENDERER.0
    );
    let found = renderings(&sources);
    let expected = vec![(THE_RENDERER.0.to_owned(), THE_RENDERER.1.to_owned())];
    assert_eq!(
        found, expected,
        "a SQL LIKE is rendered outside `{}::{}`; route a pattern through \
         `sql_like` and a literal prefix through `sql_starts_with` (`LikePrefix`)",
        THE_RENDERER.0, THE_RENDERER.1
    );
}

/// The stdlib carries no SQL `LIKE` string, and `Store`'s `StartsWith` leaf
/// renders only through `Sql.startsWith`.
#[test]
fn the_stdlib_renders_a_literal_prefix_only_through_sql_starts_with() {
    let root = e2e_support::manifest_dir!().join("../../stdlib");
    let sources = ipe_sources(&root);
    let like_strings: Vec<String> = sources
        .iter()
        .flat_map(|(name, src)| {
            ipe_string_literals(src)
                .into_iter()
                .filter(|s| renders_sql_like(s))
                .map(move |s| format!("{name}: {s:?}"))
        })
        .collect();
    assert!(
        like_strings.is_empty(),
        "a stdlib string carries SQL LIKE text:\n{}",
        like_strings.join("\n")
    );

    let store = sources
        .iter()
        .find(|(name, _)| name.ends_with("Ipe/Db/Store.ipe"))
        .map(|(_, src)| src.as_str());
    assert!(
        store.is_some(),
        "the stdlib walk did not read Ipe/Db/Store.ipe"
    );
    let (rendering, bypassing) = starts_with_renderings(store.unwrap_or_default());
    assert!(
        !rendering.is_empty(),
        "Store.ipe renders no `StartsWith` leaf; the scan would be vacuous"
    );
    assert!(
        bypassing.is_empty(),
        "a `StartsWith` leaf renders SQL without `Sql.startsWith`:\n{}",
        bypassing.join("\n")
    );
}

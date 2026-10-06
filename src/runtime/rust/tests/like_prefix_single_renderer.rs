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
//! literals. A file is dropped only when a `#[cfg(test)] mod` names it and no
//! production `mod` can; a module path the resolver does not model keeps its
//! file scanned, so a gap in the resolver turns the scan red, never vacuously
//! green.
//!
//! The stdlib half lexes every `.ipe` source with the compiler lexer's comment,
//! string and char rules, then admits `Sql.like` only inside `Store`'s `Like`
//! leaves, requires each of `Store`'s two SQL-rendering `StartsWith` leaves to
//! call `Sql.startsWith`, refuses any other import spelling of `Ipe.Db.Sql` and
//! any string naming the `Sql_like` kernel. A prefix spelled by concatenation
//! (`"LI" ++ "KE"`) is outside what a lexical scan can see.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ImplItem, ImplItemFn, Item, ItemFn, ItemMod, LitStr, Macro, Meta, Stmt,
    TraitItem,
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

/// One out-of-line `mod name;` declaration.
#[derive(Debug, PartialEq, Eq)]
struct ModDecl {
    /// The inline `mod … { }` blocks enclosing the declaration, outermost first.
    inline: Vec<String>,
    name: String,
    /// The `#[path = "…"]` value, if any.
    path: Option<String>,
    /// Whether the declaration is `#[cfg(test)]`-only.
    test: bool,
}

/// One file's production `LIKE` renderings and its out-of-line modules.
#[derive(Default)]
struct Scan {
    fn_stack: Vec<String>,
    /// The inline modules enclosing the visitor's position, outermost first.
    mod_stack: Vec<String>,
    /// The enclosing function of each production literal that renders `LIKE`.
    renders: Vec<String>,
    /// Every out-of-line `mod` declaration outside test-only code, plus each
    /// out-of-line `#[cfg(test)] mod` (an out-of-line `mod` inside a test-only
    /// inline module is not recorded, so its file stays scanned).
    mods: Vec<ModDecl>,
}

impl Scan {
    fn record(&mut self) {
        let site = self
            .fn_stack
            .last()
            .map_or_else(|| "<item>".to_owned(), Clone::clone);
        self.renders.push(site);
    }

    fn declare(&mut self, module: &ItemMod, test: bool) {
        self.mods.push(ModDecl {
            inline: self.mod_stack.clone(),
            name: module.ident.to_string(),
            path: path_attr(&module.attrs),
            test,
        });
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
                self.declare(module, true);
            }
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        if module.content.is_none() {
            self.declare(module, false);
        }
        self.mod_stack.push(module.ident.to_string());
        visit::visit_item_mod(self, module);
        self.mod_stack.pop();
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

/// `rel` under `dir`, with `.` and `..` components resolved lexically.
fn join(dir: &str, rel: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in dir.split('/').chain(rel.split('/')) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    parts.join("/")
}

/// The files `decl`, declared in `parent`, may load.
///
/// A file named `mod.rs` / `lib.rs` / `main.rs` owns its directory; any other
/// file owns the directory named after its stem, unless it was itself loaded
/// through `#[path]`, when it owns its own directory. Which applies is not
/// known per file, so `broad` yields both readings (the production side, where
/// a wider set keeps more files scanned) and the narrow reading takes the stem
/// rule only (the test side, where a wider set would drop more).
fn child_files(parent: &str, decl: &ModDecl, broad: bool) -> Vec<String> {
    let (dir, file) = parent.rsplit_once('/').unwrap_or(("", parent));
    let stem = file.strip_suffix(".rs").unwrap_or(file);
    let mut owned = Vec::new();
    if matches!(stem, "mod" | "lib" | "main") {
        owned.push(dir.to_owned());
    } else {
        owned.push(join(dir, stem));
        if broad {
            owned.push(dir.to_owned());
        }
    }
    let inline = decl.inline.join("/");
    match (&decl.path, decl.inline.is_empty()) {
        (Some(path), true) => vec![join(dir, path)],
        (Some(path), false) => owned
            .iter()
            .map(|base| join(&join(base, &inline), path))
            .collect(),
        (None, _) => owned
            .iter()
            .flat_map(|base| {
                let base = join(base, &inline);
                [
                    join(&base, &format!("{}.rs", decl.name)),
                    join(&base, &format!("{}/mod.rs", decl.name)),
                ]
            })
            .collect(),
    }
}

/// The files only a `#[cfg(test)]` module loads: each named by a test-only
/// declaration and by no production one.
fn test_only_files(scans: &[(&str, Scan)]) -> BTreeSet<String> {
    let named = |test: bool| -> BTreeSet<String> {
        scans
            .iter()
            .flat_map(|(name, scan)| {
                scan.mods
                    .iter()
                    .filter(move |decl| decl.test == test)
                    .flat_map(move |decl| child_files(name, decl, !test))
            })
            .collect()
    };
    let production = named(false);
    named(true)
        .into_iter()
        .filter(|file| !production.contains(file))
        .collect()
}

/// Every production `LIKE` rendering across `sources`, as `(file, fn)`.
fn renderings(sources: &[(String, String)]) -> Vec<(String, String)> {
    let scans: Vec<(&str, Scan)> = sources
        .iter()
        .map(|(name, src)| (name.as_str(), scan(name, src)))
        .collect();
    let test_only = test_only_files(&scans);
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

fn sources(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(name, src)| ((*name).to_owned(), (*src).to_owned()))
        .collect()
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

#[test]
fn a_file_both_a_test_and_a_production_module_load_is_kept() {
    let found = renderings(&sources(&[
        (
            "mod.rs",
            "#[cfg(test)]\n#[path = \"shared.rs\"]\nmod shared_test;\nmod shared;\n",
        ),
        ("shared.rs", r#"fn r() -> &'static str { "n LIKE ?" }"#),
    ]));
    assert_eq!(found, vec![("shared.rs".to_owned(), "r".to_owned())]);
}

#[test]
fn a_test_module_inside_an_inline_module_drops_only_its_own_file() {
    let found = renderings(&sources(&[
        (
            "mod.rs",
            "mod inner {\n    #[cfg(test)]\n    mod t;\n}\nmod t;\n",
        ),
        (
            "inner/t.rs",
            r#"fn test_side() -> &'static str { "n LIKE $1" }"#,
        ),
        ("t.rs", r#"fn production() -> &'static str { "n LIKE ?" }"#),
    ]));
    assert_eq!(found, vec![("t.rs".to_owned(), "production".to_owned())]);
}

#[test]
fn a_test_module_path_with_parent_components_is_resolved() {
    let found = renderings(&sources(&[
        (
            "web/mod.rs",
            "#[cfg(test)]\n#[path = \"../x_test.rs\"]\nmod x_test;\n",
        ),
        ("x_test.rs", r#"fn t() -> &'static str { "n LIKE $1" }"#),
        ("web/x.rs", r#"fn r() -> &'static str { "n LIKE ?" }"#),
    ]));
    assert_eq!(found, vec![("web/x.rs".to_owned(), "r".to_owned())]);
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
    assert_eq!(
        scanned.mods,
        vec![ModDecl {
            inline: Vec::new(),
            name: "db_tests".to_owned(),
            path: None,
            test: true,
        }]
    );
}

#[test]
fn an_out_of_line_module_resolves_beside_its_parent() {
    let decl = |inline: &[&str], name: &str, path: Option<&str>| ModDecl {
        inline: inline.iter().map(|m| (*m).to_owned()).collect(),
        name: name.to_owned(),
        path: path.map(str::to_owned),
        test: true,
    };
    assert_eq!(
        child_files("mod.rs", &decl(&[], "config_postgres_test", None), false),
        vec!["config_postgres_test.rs", "config_postgres_test/mod.rs"]
    );
    assert_eq!(
        child_files("web/server.rs", &decl(&[], "t", None), false),
        vec!["web/server/t.rs", "web/server/t/mod.rs"]
    );
    assert_eq!(
        child_files("web/server.rs", &decl(&[], "t", None), true),
        vec![
            "web/server/t.rs",
            "web/server/t/mod.rs",
            "web/t.rs",
            "web/t/mod.rs"
        ]
    );
    assert_eq!(
        child_files("web/mod.rs", &decl(&[], "t", Some("t_tests.rs")), false),
        vec!["web/t_tests.rs"]
    );
    assert_eq!(
        child_files("web/mod.rs", &decl(&[], "t", Some("./t_tests.rs")), false),
        vec!["web/t_tests.rs"]
    );
    assert_eq!(
        child_files("web/mod.rs", &decl(&["a", "b"], "t", None), false),
        vec!["web/a/b/t.rs", "web/a/b/t/mod.rs"]
    );
    assert_eq!(
        child_files("web/server.rs", &decl(&["a"], "t", Some("u.rs")), false),
        vec!["web/server/a/u.rs"]
    );
}

#[test]
fn a_test_only_file_is_dropped_and_a_production_file_is_kept() {
    let found = renderings(&sources(&[
        ("mod.rs", "#[cfg(test)]\nmod pg_test;\nmod live;\n"),
        ("pg_test.rs", r#"fn t() -> &'static str { "n LIKE $1" }"#),
        ("live.rs", r#"fn r() -> &'static str { "n LIKE ?" }"#),
    ]));
    assert_eq!(found, vec![("live.rs".to_owned(), "r".to_owned())]);
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = fixture("fn production( { \"n LIKE ?\" }");
}

// ---------------------------------------------------------------------------
// The stdlib half: `StartsWith` renders through `Sql.startsWith`, `Sql.like`
// is called only by a `Like` leaf, and no stdlib string carries SQL `LIKE`
// text or names the `Sql_like` kernel.
// ---------------------------------------------------------------------------

/// The `Store` leaves that render a `StartsWith` condition to SQL: one in
/// `condFragmentIn`, one in `condFragmentInQualified`.
const STARTS_WITH_RENDERINGS: usize = 2;

/// The only spelling under which the stdlib imports the `Sql` kernels, so a
/// `Sql.like` call cannot hide behind another qualifier or an `exposing` list.
const SQL_IMPORT: [&str; 4] = ["import", "Ipe.Db.Sql", "as", "Sql"];

/// The registry key of the `Sql.like` kernel, which `Kernel.kernel` could bind
/// under another name.
const SQL_LIKE_KERNEL: &str = "Sql_like";

/// Why an Ipê source could not be lexed.
#[derive(Debug, PartialEq, Eq)]
enum IpeLexError {
    UnterminatedComment,
    UnterminatedString,
    MalformedChar,
}

/// An Ipê source split the way the compiler's lexer splits it: `code` keeps
/// every character outside comments and literals (each literal becomes `""` or
/// `' '`, each comment is dropped, every newline is kept so line structure
/// survives), `strings` holds each string literal's text, and a triple-quoted
/// string's `{{…}}` interpolations go back into `code`.
#[derive(Debug, Default)]
struct IpeLex {
    code: String,
    strings: Vec<String>,
}

/// Lexes `src` with the comment, string and char rules of
/// `src/compiler/parse/src/lexer.rs`.
fn lex_ipe(src: &str) -> Result<IpeLex, IpeLexError> {
    let chars: Vec<char> = src.chars().collect();
    let mut lex = IpeLex::default();
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        match (c, chars.get(i + 1)) {
            ('-', Some('-')) => {
                while chars.get(i).is_some_and(|&c| c != '\n') {
                    i += 1;
                }
            }
            ('{', Some('-')) => i = skip_block_comment(&chars, i, &mut lex.code)?,
            ('"', _) => i = lex_string(&chars, i, &mut lex)?,
            ('\'', _) => {
                i = lex_char(&chars, i)?;
                lex.code.push_str("' '");
            }
            _ => {
                lex.code.push(c);
                i += 1;
            }
        }
    }
    Ok(lex)
}

/// Skips the block comment opening at `start`: `{- … -}` nests, a `{-| … -}`
/// doc comment ends at its first `-}`. Returns the index past the comment.
fn skip_block_comment(
    chars: &[char],
    start: usize,
    code: &mut String,
) -> Result<usize, IpeLexError> {
    let doc = chars.get(start + 2) == Some(&'|');
    let mut i = start + 2;
    let mut depth: u32 = 1;
    loop {
        match (chars.get(i), chars.get(i + 1)) {
            (None, _) => return Err(IpeLexError::UnterminatedComment),
            (Some('-'), Some('}')) => {
                i += 2;
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(i);
                }
            }
            (Some('{'), Some('-')) if !doc => {
                i += 2;
                depth = depth.saturating_add(1);
            }
            (Some('\n'), _) => {
                code.push('\n');
                i += 1;
            }
            (Some(_), _) => i += 1,
        }
    }
}

/// Lexes the string literal opening at `start` (`"…"` on one line with
/// escapes, or a raw `"""…"""` closed by the first three quotes). Returns the
/// index past the literal.
fn lex_string(chars: &[char], start: usize, lex: &mut IpeLex) -> Result<usize, IpeLexError> {
    let triple = chars.get(start + 1) == Some(&'"') && chars.get(start + 2) == Some(&'"');
    let mut text = String::new();
    let mut i = if triple { start + 3 } else { start + 1 };
    let end = loop {
        match (chars.get(i), triple) {
            (None, _) | (Some('\n' | '\r'), false) => return Err(IpeLexError::UnterminatedString),
            (Some('"'), false) => break i + 1,
            (Some('"'), true)
                if chars.get(i + 1) == Some(&'"') && chars.get(i + 2) == Some(&'"') =>
            {
                break i + 3;
            }
            (Some('\\'), false) => {
                let escaped = chars.get(i + 1).ok_or(IpeLexError::UnterminatedString)?;
                text.push(*escaped);
                i += 2;
            }
            (Some(&c), _) => {
                text.push(c);
                i += 1;
            }
        }
    };
    lex.code.push_str("\"\"");
    if triple {
        for interpolation in interpolations(&text) {
            lex.code.push(' ');
            lex.code.push_str(interpolation);
        }
        lex.code.extend(text.chars().filter(|&c| c == '\n'));
    }
    lex.strings.push(text);
    Ok(end)
}

/// The `{{…}}` interpolation bodies of a triple-quoted string's raw text.
fn interpolations(raw: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut rest = raw;
    while let Some((_, after)) = rest.split_once("{{") {
        let Some((body, tail)) = after.split_once("}}") else {
            found.push(after);
            break;
        };
        found.push(body);
        rest = tail;
    }
    found
}

/// Lexes the char literal opening at `start` (`'c'` or `'\x'`). Returns the
/// index past the literal.
fn lex_char(chars: &[char], start: usize) -> Result<usize, IpeLexError> {
    let close = match chars.get(start + 1) {
        Some('\\') => start + 3,
        Some('\'') | None => return Err(IpeLexError::MalformedChar),
        Some(_) => start + 2,
    };
    if chars.get(close) == Some(&'\'') {
        Ok(close + 1)
    } else {
        Err(IpeLexError::MalformedChar)
    }
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The statement whose first line is `lines[start]`: that line plus every
/// following blank line or line indented deeper than it.
fn block_at(lines: &[&str], start: usize) -> String {
    let Some(head) = lines.get(start) else {
        return String::new();
    };
    let depth = indent(head);
    let mut block = String::from(*head);
    for line in lines.iter().skip(start + 1) {
        if !line.trim().is_empty() && indent(line) <= depth {
            break;
        }
        block.push('\n');
        block.push_str(line);
    }
    block
}

/// The body of each `ctor … ->` case arm in `code`: the text after the arrow
/// plus every line indented deeper than the arm.
fn arm_bodies(code: &str, ctor: &str) -> Vec<String> {
    let lines: Vec<&str> = code.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            let head = line.trim_start();
            head.strip_prefix(ctor)
                .is_some_and(|rest| rest.starts_with(' ') && rest.contains("->"))
        })
        .map(|(at, _)| {
            let block = block_at(&lines, at);
            block
                .split_once("->")
                .map_or_else(String::new, |(_, body)| body.to_owned())
        })
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// How many times `code` names `qualified` as a whole word (a longer module
/// path such as `Ipe.Db.Sql.like` counts too).
fn count_word(code: &str, qualified: &str) -> usize {
    code.match_indices(qualified)
        .filter(|(at, _)| {
            let before = code.get(..*at).and_then(|s| s.chars().next_back());
            let after = code
                .get(at + qualified.len()..)
                .and_then(|s| s.chars().next());
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// Every way `sources` let a literal prefix reach SQL other than through
/// `Sql.startsWith`, as messages.
fn stdlib_violations(sources: &[(String, String)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut lexed = Vec::new();
    for (name, src) in sources {
        match lex_ipe(src) {
            Ok(lex) => lexed.push((name.as_str(), lex)),
            Err(err) => violations.push(format!("{name}: does not lex ({err:?})")),
        }
    }
    let mut sql_like_calls = 0usize;
    for (name, lex) in &lexed {
        for text in &lex.strings {
            if renders_sql_like(text) {
                violations.push(format!("{name}: a string carries SQL LIKE text: {text:?}"));
            }
            if text == SQL_LIKE_KERNEL {
                violations.push(format!(
                    "{name}: a string names the `{SQL_LIKE_KERNEL}` kernel"
                ));
            }
        }
        let lines: Vec<&str> = lex.code.lines().collect();
        for (at, line) in lines.iter().enumerate() {
            let words: Vec<&str> = line.split_whitespace().collect();
            if words.first() == SQL_IMPORT.first() && words.get(1) == SQL_IMPORT.get(1) {
                let statement = block_at(&lines, at);
                let spelled: Vec<&str> = statement.split_whitespace().collect();
                if spelled != SQL_IMPORT {
                    violations.push(format!(
                        "{name}: `{}` imports `Ipe.Db.Sql` other than as `{}`",
                        spelled.join(" "),
                        SQL_IMPORT.join(" ")
                    ));
                }
            }
        }
        sql_like_calls += count_word(&lex.code, "Sql.like");
    }

    let Some((_, store)) = lexed
        .iter()
        .find(|(name, _)| name.ends_with("Ipe/Db/Store.ipe"))
    else {
        violations.push("the stdlib walk did not read Ipe/Db/Store.ipe".to_owned());
        return violations;
    };
    let rendering: Vec<String> = arm_bodies(&store.code, "StartsWith")
        .into_iter()
        .filter(|body| body.contains("Sql."))
        .collect();
    if rendering.len() != STARTS_WITH_RENDERINGS {
        violations.push(format!(
            "Store.ipe renders {} `StartsWith` leaves to SQL, not {STARTS_WITH_RENDERINGS}",
            rendering.len()
        ));
    }
    for body in &rendering {
        if count_word(body, "Sql.startsWith") == 0 || count_word(body, "Sql.like") > 0 {
            violations.push(format!(
                "a `StartsWith` leaf renders SQL without `Sql.startsWith`:{body}"
            ));
        }
    }
    let like_leaf_calls: usize = arm_bodies(&store.code, "Like")
        .iter()
        .map(|body| count_word(body, "Sql.like"))
        .sum();
    if sql_like_calls != like_leaf_calls {
        violations.push(format!(
            "`Sql.like` is called {sql_like_calls} times in the stdlib but {like_leaf_calls} \
             times by a `Like` leaf; a literal prefix must go through `Sql.startsWith`"
        ));
    }
    violations
}

/// A `Store.ipe` whose leaves all render through their own kernel.
const STORE_FIXTURE: &str = r"import Ipe.Db.Sql as Sql

condFragmentIn view cond =
    case cond of
        Like col pattern ->
            Result.map (\live -> Sql.like (Sql.column live) pattern) (liveName view col)

        StartsWith col prefix ->
            Result.map (\live -> Sql.startsWith (Sql.column live) prefix) (liveName view col)

condFragmentInQualified alias view cond =
    case cond of
        Like col pattern ->
            Result.map (\live -> Sql.like (Sql.column (qualified alias live)) pattern) (liveName view col)

        StartsWith col prefix ->
            Result.map (\live -> Sql.startsWith (Sql.column (qualified alias live)) prefix) (liveName view col)

recastCond cond =
    case cond of
        StartsWith col prefix ->
            StartsWith col prefix
";

fn store_violations(store: &str) -> Vec<String> {
    stdlib_violations(&sources(&[("Ipe/Db/Store.ipe", store)]))
}

/// `STORE_FIXTURE` with its first `from` replaced by `to`.
fn store_with(from: &str, to: &str) -> String {
    assert!(STORE_FIXTURE.contains(from), "the fixture spells {from:?}");
    STORE_FIXTURE.replacen(from, to, 1)
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
fn a_store_whose_leaves_render_through_their_own_kernels_is_admitted() {
    assert_eq!(store_violations(STORE_FIXTURE), Vec::<String>::new());
}

#[test]
fn a_starts_with_leaf_rendered_through_like_is_caught() {
    let store = store_with(
        r"Sql.startsWith (Sql.column live) prefix",
        r"Sql.like (Sql.column live) (escape prefix)",
    );
    let found = store_violations(&store);
    assert!(
        found.iter().any(|v| v.contains("without `Sql.startsWith`")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("`Sql.like` is called 3 times")),
        "{found:?}"
    );
}

#[test]
fn a_bypass_on_a_continuation_line_is_caught() {
    let store = store_with(
        r"Result.map (\live -> Sql.startsWith (Sql.column live) prefix) (liveName view col)",
        "Result.map\n                (\\live -> Sql.like (Sql.column live) (escape prefix))\n                (liveName view col)",
    );
    let found = store_violations(&store);
    assert!(
        found.iter().any(|v| v.contains("without `Sql.startsWith`")),
        "{found:?}"
    );
}

#[test]
fn a_bypass_through_a_helper_is_caught() {
    let mut store = store_with(
        r"Result.map (\live -> Sql.startsWith (Sql.column live) prefix) (liveName view col)",
        "prefixFragment view col prefix",
    );
    store.push_str("\nprefixFragment view col prefix =\n    Result.map (\\live -> Sql.like (Sql.column live) (escape prefix)) (liveName view col)\n");
    let found = store_violations(&store);
    assert!(
        found
            .iter()
            .any(|v| v.contains("renders 1 `StartsWith` leaves")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("`Sql.like` is called 3 times")),
        "{found:?}"
    );
}

#[test]
fn a_renamed_or_exposing_sql_import_is_caught() {
    for import in [
        "import Ipe.Db.Sql as S",
        "import Ipe.Db.Sql exposing (like)",
        "import Ipe.Db.Sql as Sql\n    exposing (like)",
        "import Ipe.Db.Sql",
    ] {
        let found = store_violations(&store_with("import Ipe.Db.Sql as Sql", import));
        assert!(
            found
                .iter()
                .any(|v| v.contains("imports `Ipe.Db.Sql` other than")),
            "{import}: {found:?}"
        );
    }
}

#[test]
fn a_kernel_binding_of_sql_like_is_caught() {
    let mut store = STORE_FIXTURE.to_owned();
    store.push_str("\nprefixLike = Kernel.kernel \"Sql_like\"\n");
    let found = store_violations(&store);
    assert!(
        found
            .iter()
            .any(|v| v.contains("names the `Sql_like` kernel")),
        "{found:?}"
    );
}

#[test]
fn like_strings_are_caught_wherever_the_lexer_keeps_them() {
    for (shape, src) in [
        (
            "single-line",
            r#"frag = Sql.raw "n LIKE ? ESCAPE '\\'" -- "x""#,
        ),
        (
            "triple-quoted over lines",
            "frag = Sql.raw \"\"\"\n    n\n    LIKE ?\n\"\"\"",
        ),
        (
            "after a quote char",
            "q = '\"'\nfrag = Sql.raw \"n LIKE ?\"",
        ),
        (
            "after a nested comment",
            "{- {- -} \" -}\nfrag = Sql.raw \"n LIKE ?\"",
        ),
    ] {
        let found = stdlib_violations(&sources(&[("Ipe/Raw.ipe", src)]));
        assert!(
            found.iter().any(|v| v.contains("carries SQL LIKE text")),
            "{shape}: {found:?}"
        );
    }
}

#[test]
fn comments_and_prose_strings_are_not_like_text() {
    let src = "-- Sql.raw \"n LIKE ?\"\n{- \"n LIKE ?\" {- nested -} \"n LIKE ?\" -}\n{-| `n LIKE ?` {- -}\nlabel = \"like a charm\"\n";
    let lex = lex_ipe(src);
    assert!(lex.is_ok(), "{lex:?}");
    let lex = lex.unwrap_or_default();
    assert_eq!(lex.strings, vec!["like a charm"]);
    assert_eq!(lex.code.lines().count(), src.lines().count());
}

#[test]
fn a_triple_quoted_interpolation_is_code() {
    let lex = lex_ipe("s = \"\"\"a {{ Sql.like c p }} b\"\"\"\n");
    assert!(lex.is_ok(), "{lex:?}");
    assert_eq!(count_word(&lex.unwrap_or_default().code, "Sql.like"), 1);
}

#[test]
fn an_unlexable_source_is_a_violation() {
    for (src, err) in [
        ("{- open", IpeLexError::UnterminatedComment),
        ("s = \"open\nt = 1", IpeLexError::UnterminatedString),
        ("c = 'ab'", IpeLexError::MalformedChar),
    ] {
        assert_eq!(lex_ipe(src).err(), Some(err), "{src:?}");
    }
    let found = stdlib_violations(&sources(&[("Ipe/Raw.ipe", "{- open")]));
    assert!(
        found.iter().any(|v| v.contains("does not lex")),
        "{found:?}"
    );
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

/// The stdlib carries no SQL `LIKE` string and binds `Sql.like` only in a
/// `Like` leaf, and `Store`'s `StartsWith` leaves render only through
/// `Sql.startsWith`.
#[test]
fn the_stdlib_renders_a_literal_prefix_only_through_sql_starts_with() {
    let root = e2e_support::manifest_dir!().join("../../stdlib");
    let violations = stdlib_violations(&ipe_sources(&root));
    assert!(
        violations.is_empty(),
        "the stdlib renders a literal prefix outside `Sql.startsWith`:\n{}",
        violations.join("\n")
    );
}

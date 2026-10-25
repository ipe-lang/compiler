#![forbid(unsafe_code)]
//! Every host program ipe spawns is reached through one absolute-only resolver.
//!
//! A resolver that joins every `PATH` entry, or a `Command::new("name")` that
//! lets the OS search `PATH` itself, lets a relative entry (the untrusted
//! project's own directory) supply the program. `ipe_sandbox::host_tool` is the
//! one place `PATH` is parsed: it admits only absolute entries holding an
//! executable regular file and hands back a `ToolPath`.
//!
//! The scan runs over every `.rs` file under `src/` and `tools/`, parsed with
//! `syn` through `panic_scan`, the front-end `tools/panic-scan` uses. Test code
//! is a `tests` directory, a `tests.rs` file, or an item whose `cfg` is
//! test-only by [`panic_scan::test_only_item_lines`]; every other line is
//! production. In production code it refuses:
//!
//! 1. a `split_paths` or `join_paths` identifier outside the resolver
//!    ([`RESOLVER`]);
//! 2. a `Command::new(<program>)` (through any `use … as` rename or `type`
//!    alias of `Command`, and as `<Command>::new`) or `.command(<program>)`
//!    whose program is a
//!    relative string literal, a `PathBuf`/`Path`/`OsStr`/`OsString`/`String`
//!    built from one, or a name the same fn (or a file-level `const`/`static`)
//!    binds to one. An absolute literal names no `PATH` search, and a program
//!    held in a typed value (`tool.as_path()`, a parameter) is admitted: the
//!    type system owns it.
//!
//! Macro bodies are walked token by token under both rules. A file that does
//! not parse is red, never skipped.
//!
//! The sites not yet moved onto the resolver are held to
//! `tool_path_scan/pending.txt`, a shrink-only ratchet: a file with more sites
//! than its line allows is red, and so is a line that allows more than the file
//! has.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMethodCall, Lit, Macro, Pat, Type};

/// The source roots scanned, relative to the repository root.
const ROOTS: &[&str] = &["src", "tools"];

/// Directory names never descended into, each a `**/<name>` line of the
/// repository `.gitignore`; a dot-directory is likewise ignored output or tool
/// config, never a Rust module.
const SKIPPED_DIRS: &[&str] = &["target", "out", "node_modules"];

/// The one file that may parse `PATH`.
const RESOLVER: &str = "src/compiler/sandbox/src/host_tool.rs";

/// The identifiers of a `PATH` walk.
const PATH_WALKS: &[&str] = &["split_paths", "join_paths"];

/// The types a program literal may be wrapped in on its way to a spawn.
const WRAPPERS: &[&str] = &["PathBuf", "Path", "OsStr", "OsString", "String"];

/// The conversions that keep a literal a literal.
const CONVERSIONS: &[&str] = &["to_string", "to_owned", "into", "as_ref"];

/// The ratchet of sites not yet moved onto the resolver.
const PENDING: &str = include_str!("tool_path_scan/pending.txt");

/// Which rule a site breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A `PATH` walk outside the resolver.
    PathWalk,
    /// A spawn of a program named by a relative literal.
    LiteralProgram,
}

/// One refused site in a file.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Site {
    /// 1-based line of the site's first token.
    line: usize,
    /// The rule it breaks.
    kind: Kind,
    /// The identifier or the program text, for the report.
    text: String,
}

/// The 1-based line `span` starts on.
fn line_of(span: Span) -> usize {
    span.start().line
}

/// Whether `text` names a program the OS would search `PATH` for.
fn is_relative_program(text: &str) -> bool {
    !Path::new(text).has_root()
}

/// Whether `tree` is the punctuation `ch`.
fn is_punct(tree: Option<&TokenTree>, ch: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

/// The last segment of the type `ty` names, through groups and parentheses.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.unraw().to_string()),
        Type::Group(group) => type_name(&group.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        _ => None,
    }
}

/// The last segment of `expr` when it is a path, with the type it is
/// associated to: the qualified self type of `<T>::f` or `<T as Trait>::f`,
/// otherwise the segment before the last.
fn tail_segments(expr: &Expr) -> Option<(Option<String>, String)> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let mut segments = path.path.segments.iter().rev();
    let last = segments.next()?.ident.unraw().to_string();
    let parent = match &path.qself {
        Some(qself) => type_name(&qself.ty),
        None => segments.next().map(|s| s.ident.unraw().to_string()),
    };
    Some((parent, last))
}

/// The names bound to a relative program literal in one scope.
#[derive(Clone, Default)]
struct Literals {
    /// Names bound to such a literal.
    names: BTreeSet<String>,
}

impl Literals {
    /// The relative program literal `expr` evaluates to, if it is one.
    fn program_of(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(s) if is_relative_program(&s.value()) => Some(s.value()),
                _ => None,
            },
            Expr::Reference(r) => self.program_of(&r.expr),
            Expr::Paren(p) => self.program_of(&p.expr),
            Expr::Group(g) => self.program_of(&g.expr),
            Expr::Call(call) => {
                let (Some(parent), last) = tail_segments(&call.func)? else {
                    return None;
                };
                if WRAPPERS.contains(&parent.as_str()) && (last == "from" || last == "new") {
                    self.program_of(call.args.first()?)
                } else {
                    None
                }
            }
            Expr::MethodCall(call) if CONVERSIONS.contains(&call.method.to_string().as_str()) => {
                self.program_of(&call.receiver)
            }
            Expr::Path(path) => {
                let ident = path.path.get_ident()?.unraw().to_string();
                self.names.contains(&ident).then_some(ident)
            }
            _ => None,
        }
    }
}

/// The name a `let` pattern binds, when it binds exactly one.
fn bound_name(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) => Some(ident.ident.unraw().to_string()),
        Pat::Type(typed) => bound_name(&typed.pat),
        _ => None,
    }
}

/// Collect the literal bindings of one fn body, not descending into nested
/// items (each nested fn is its own scope).
struct Bindings {
    /// The bindings found so far.
    literals: Literals,
}

impl<'ast> Visit<'ast> for Bindings {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (Some(name), Some(init)) = (bound_name(&local.pat), &local.init)
            && self.literals.program_of(&init.expr).is_some()
        {
            self.literals.names.insert(name);
        }
        visit::visit_local(self, local);
    }

    fn visit_item(&mut self, _item: &'ast syn::Item) {}
}

/// The names `Command` goes by in one file, renames and aliases included.
struct CommandNames {
    /// `Command` and every `use … as` rename or `type` alias of it.
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for CommandNames {
    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        if self.names.contains(&rename.ident.unraw().to_string()) {
            self.names.insert(rename.rename.unraw().to_string());
        }
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if type_name(&item.ty).is_some_and(|name| self.names.contains(&name)) {
            self.names.insert(item.ident.unraw().to_string());
        }
        visit::visit_item_type(self, item);
    }
}

/// The names `Command` goes by in `file`, walked to a fixpoint so a rename or
/// alias declared before the name it renames is still followed. A pass that
/// does not stop adds a name, and a file declares finitely many.
fn command_names(file: &syn::File) -> BTreeSet<String> {
    let mut names = CommandNames {
        names: BTreeSet::from([String::from("Command")]),
    };
    loop {
        let before = names.names.len();
        names.visit_file(file);
        if names.names.len() == before {
            return names.names;
        }
    }
}

/// The refused sites of one parsed file.
struct Spawns {
    /// Whether rule 1 applies to this file.
    judge_walks: bool,
    /// The names `Command` goes by.
    commands: BTreeSet<String>,
    /// The file-level literal bindings.
    file: Literals,
    /// The literal bindings in scope.
    scope: Literals,
    /// The sites found so far.
    sites: Vec<Site>,
}

impl Spawns {
    /// Record a site.
    fn site(&mut self, span: Span, kind: Kind, text: String) {
        self.sites.push(Site {
            line: line_of(span),
            kind,
            text,
        });
    }

    /// Judge `block` with its own literal bindings in scope.
    fn in_fn_scope(&mut self, visit_body: impl FnOnce(&mut Self, &mut Bindings)) {
        let mut bindings = Bindings {
            literals: self.file.clone(),
        };
        let outer = std::mem::take(&mut self.scope);
        visit_body(self, &mut bindings);
        self.scope = outer;
    }

    /// Judge a spawn whose program is `program`, spawned at `span`.
    fn spawn(&mut self, span: Span, program: Option<&Expr>) {
        if let Some(text) = program.and_then(|p| self.scope.program_of(p)) {
            self.site(span, Kind::LiteralProgram, text);
        }
    }

    /// Judge a macro body token by token.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.unraw().to_string();
                    if self.judge_walks && PATH_WALKS.contains(&name.as_str()) {
                        self.site(ident.span(), Kind::PathWalk, name);
                    } else if self.commands.contains(&name)
                        && is_punct(trees.get(at.saturating_add(1)), ':')
                        && is_punct(trees.get(at.saturating_add(2)), ':')
                        && matches!(trees.get(at.saturating_add(3)), Some(TokenTree::Ident(n)) if n == "new")
                        && let Some(TokenTree::Group(args)) = trees.get(at.saturating_add(4))
                        && args.delimiter() == Delimiter::Parenthesis
                        && let Some(TokenTree::Literal(first)) = args.stream().into_iter().next()
                        && let Lit::Str(program) = Lit::new(first)
                        && is_relative_program(&program.value())
                    {
                        self.site(ident.span(), Kind::LiteralProgram, program.value());
                    }
                }
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Spawns {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.in_fn_scope(|this, bindings| {
            bindings.visit_block(&item.block);
            this.scope = bindings.literals.clone();
            visit::visit_item_fn(this, item);
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.in_fn_scope(|this, bindings| {
            bindings.visit_block(&item.block);
            this.scope = bindings.literals.clone();
            visit::visit_impl_item_fn(this, item);
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.in_fn_scope(|this, bindings| {
            if let Some(block) = &item.default {
                bindings.visit_block(block);
            }
            this.scope = bindings.literals.clone();
            visit::visit_trait_item_fn(this, item);
        });
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        let name = ident.unraw().to_string();
        if self.judge_walks && PATH_WALKS.contains(&name.as_str()) {
            self.site(ident.span(), Kind::PathWalk, name);
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.tokens(mac.tokens.clone());
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Some((Some(parent), last)) = tail_segments(&call.func)
            && self.commands.contains(&parent)
            && last == "new"
        {
            let span = match &*call.func {
                Expr::Path(path) => path
                    .path
                    .segments
                    .first()
                    .map_or_else(Span::call_site, |segment| segment.ident.span()),
                _ => Span::call_site(),
            };
            self.spawn(span, call.args.first());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "command" && call.args.len() == 1 {
            self.spawn(call.method.span(), call.args.first());
        }
        visit::visit_expr_method_call(self, call);
    }
}

/// The file-level `const`/`static` names bound to a relative program literal.
fn file_literals(file: &syn::File) -> Literals {
    let mut literals = Literals::default();
    for item in &file.items {
        let (ident, expr) = match item {
            syn::Item::Const(c) => (&c.ident, &*c.expr),
            syn::Item::Static(s) => (&s.ident, &*s.expr),
            _ => continue,
        };
        if literals.program_of(expr).is_some() {
            literals.names.insert(ident.unraw().to_string());
        }
    }
    literals
}

/// The refused production sites of the file at `rel` holding `src`.
///
/// # Errors
///
/// A message naming `rel` when it does not parse or is over a parse ceiling.
fn scan_source(rel: &str, src: &str) -> Result<Vec<Site>, String> {
    let test_lines = panic_scan::test_only_item_lines(src)
        .map_err(|e| format!("{rel}: does not parse, so it cannot be judged: {e}"))?;
    let sites = panic_scan::with_parsed(src, |file| {
        let literals = file_literals(file);
        let mut spawns = Spawns {
            judge_walks: rel != RESOLVER,
            commands: command_names(file),
            scope: literals.clone(),
            file: literals,
            sites: Vec::new(),
        };
        spawns.visit_file(file);
        spawns.sites
    })
    .map_err(|e| format!("{rel}: does not parse, so it cannot be judged: {e}"))?;
    Ok(sites
        .into_iter()
        .filter(|site| !test_lines.iter().any(|span| span.contains(&site.line)))
        .collect())
}

/// Every production `.rs` file under the scanned roots of `repo`, as its path
/// relative to `repo` with `/` separators, and every path the walk could not
/// judge: an unreadable directory or entry, or a symlinked directory the walk
/// does not follow, is red, never silently skipped.
fn production_files(repo: &Path) -> (Vec<(String, PathBuf)>, Vec<String>) {
    let mut found = Vec::new();
    let mut unjudged = Vec::new();
    let mut pending: Vec<PathBuf> = ROOTS.iter().map(|root| repo.join(root)).collect();
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                unjudged.push(format!("{}: cannot be listed: {e}", dir.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    unjudged.push(format!("{}: an entry cannot be read: {e}", dir.display()));
                    continue;
                }
            };
            let path = entry.path();
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(e) => {
                    unjudged.push(format!("{}: cannot be typed: {e}", path.display()));
                    continue;
                }
            };
            if kind.is_symlink() && path.is_dir() {
                unjudged.push(format!(
                    "{}: a symlinked directory is not followed",
                    path.display()
                ));
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_str()) {
                    pending.push(path);
                }
                continue;
            }
            let Ok(rel) = path.strip_prefix(repo) else {
                unjudged.push(format!("{}: is outside the repository", path.display()));
                continue;
            };
            if path.extension().is_none_or(|e| e != "rs")
                || panic_scan::is_verified_test_path(repo, rel)
            {
                continue;
            }
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            found.push((rel, path));
        }
    }
    found.sort();
    (found, unjudged)
}

/// The ratchet: each file's allowed site count.
///
/// # Errors
///
/// A message naming the line when one is malformed, repeats a file, or allows
/// zero sites.
fn pending_counts(text: &str) -> Result<BTreeMap<String, usize>, String> {
    let mut counts = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index.saturating_add(1);
        let mut fields = line.split_whitespace();
        let (Some(rel), Some(count), None) = (fields.next(), fields.next(), fields.next()) else {
            return Err(format!("pending.txt:{number}: expected `<path> <count>`"));
        };
        let count: usize = count
            .parse()
            .map_err(|e| format!("pending.txt:{number}: count `{count}`: {e}"))?;
        if count == 0 {
            return Err(format!(
                "pending.txt:{number}: a zero count is a stale line"
            ));
        }
        if counts.insert(rel.to_owned(), count).is_some() {
            return Err(format!("pending.txt:{number}: {rel} is listed twice"));
        }
    }
    Ok(counts)
}

/// The ratchet's verdict on the sites found: one line per disagreeing file.
fn ratchet_problems(
    found: &BTreeMap<String, Vec<Site>>,
    allowed: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for (rel, sites) in found {
        let limit = allowed.get(rel).copied().unwrap_or(0);
        if sites.len() > limit {
            let listed = sites
                .iter()
                .map(|site| format!("    {rel}:{} {:?} {}", site.line, site.kind, site.text))
                .collect::<Vec<_>>()
                .join("\n");
            problems.push(format!(
                "{rel}: {} site(s), pending.txt allows {limit}; resolve the program through \
                 `ipe_sandbox::host_tool` and spawn its `ToolPath`:\n{listed}",
                sites.len()
            ));
        } else if sites.len() < limit {
            problems.push(format!(
                "{rel}: {} site(s) left; lower its pending.txt count to {}",
                sites.len(),
                sites.len()
            ));
        }
    }
    for rel in allowed.keys() {
        if !found.contains_key(rel) {
            problems.push(format!("{rel}: no site left; remove its pending.txt line"));
        }
    }
    problems
}

#[test]
fn the_tree_has_no_unlisted_site() {
    let repo = e2e_support::manifest_dir!().join("../..");
    let (files, mut unjudged) = production_files(&repo);
    assert!(
        files.len() > 100,
        "only {} production files found under {}",
        files.len(),
        repo.display()
    );
    assert!(
        files.iter().any(|(rel, _)| rel == RESOLVER),
        "the resolver {RESOLVER} is not among the scanned files"
    );
    let allowed = pending_counts(PENDING).expect("pending.txt parses");

    let mut found = BTreeMap::new();
    for (rel, path) in &files {
        let src = match panic_scan::read_source(path) {
            Ok(src) => src,
            Err(e) => {
                unjudged.push(format!("{rel}: cannot be read: {e}"));
                continue;
            }
        };
        match scan_source(rel, &src) {
            Ok(sites) if sites.is_empty() => {}
            Ok(sites) => {
                found.insert(rel.clone(), sites);
            }
            Err(e) => unjudged.push(e),
        }
    }
    assert!(
        unjudged.is_empty(),
        "a file the scan cannot judge is red:\n  {}",
        unjudged.join("\n  ")
    );
    let problems = ratchet_problems(&found, &allowed);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The path a fixture is judged at: production, outside the resolver.
const FIXTURE_PATH: &str = "src/fixture.rs";

/// The kinds of the sites the scan finds in `src` at `rel`.
#[allow(clippy::expect_used)] // test helper: a fixture that does not parse IS the failure
fn kinds(rel: &str, src: &str) -> Vec<Kind> {
    scan_source(rel, src)
        .expect("fixture parses")
        .into_iter()
        .map(|site| site.kind)
        .collect()
}

#[test]
fn a_path_walk_outside_the_resolver_is_refused() {
    let src = "pub fn f(p: &std::ffi::OsStr) -> usize { std::env::split_paths(&p).count() }\n";
    assert_eq!(kinds(FIXTURE_PATH, src), [Kind::PathWalk]);
    assert_eq!(
        kinds(RESOLVER, src),
        Vec::<Kind>::new(),
        "the resolver walks"
    );
    let joined = "pub fn f() { let _ = std::env::join_paths([\"a\"]); }\n";
    assert_eq!(kinds(FIXTURE_PATH, joined), [Kind::PathWalk]);
    let imported = "use std::env::split_paths as walk;\npub fn f() {}\n";
    assert_eq!(kinds(FIXTURE_PATH, imported), [Kind::PathWalk]);
}

#[test]
fn a_literal_program_is_refused() {
    let src = "pub fn f() { let _ = std::process::Command::new(\"git\"); }\n";
    assert_eq!(kinds(FIXTURE_PATH, src), [Kind::LiteralProgram]);
    assert_eq!(
        kinds(RESOLVER, src),
        [Kind::LiteralProgram],
        "the resolver is exempt from the walk rule only"
    );
    let wrapped = "pub fn f() { let _ = Command::new(std::path::PathBuf::from(\"cargo\")); }\n";
    assert_eq!(kinds(FIXTURE_PATH, wrapped), [Kind::LiteralProgram]);
    let tokio = "pub fn f() { let _ = tokio::process::Command::new(OsStr::new(\"curl\")); }\n";
    assert_eq!(kinds(FIXTURE_PATH, tokio), [Kind::LiteralProgram]);
    let renamed = "use std::process::Command as Spawn;\n\
                   pub fn f() { let _ = Spawn::new(\"git\"); m!(Spawn::new(\"sh\")); }\n";
    assert_eq!(
        kinds(FIXTURE_PATH, renamed),
        [Kind::LiteralProgram, Kind::LiteralProgram]
    );
    let grouped = "use std::process::{Command as Spawn, Stdio};\n\
                   pub fn f() { let _ = Spawn::new(\"git\"); }\n";
    assert_eq!(kinds(FIXTURE_PATH, grouped), [Kind::LiteralProgram]);
}

#[test]
fn a_qualified_or_aliased_command_is_refused() {
    let qualified = "pub fn f() { let _ = <Command>::new(\"git\"); \
                     let _ = <std::process::Command as Spawner>::new(\"sh\"); }\n";
    assert_eq!(
        kinds(FIXTURE_PATH, qualified),
        [Kind::LiteralProgram, Kind::LiteralProgram]
    );
    let aliased = "type Cmd = Spawn;\nuse std::process::Command as Spawn;\n\
                   pub fn f() { let _ = Cmd::new(\"git\"); }\n";
    assert_eq!(
        kinds(FIXTURE_PATH, aliased),
        [Kind::LiteralProgram],
        "an alias declared before its rename is still followed"
    );
    let unrelated = "type Cmd = Vec<u8>;\npub fn f() { let _ = Cmd::new(\"git\"); }\n";
    assert_eq!(kinds(FIXTURE_PATH, unrelated), Vec::<Kind>::new());
}

#[test]
fn a_literal_bound_by_name_is_refused() {
    let local = "pub fn f() { let program: &str = \"sh\"; let _ = Command::new(program); }\n";
    assert_eq!(kinds(FIXTURE_PATH, local), [Kind::LiteralProgram]);
    let owned = "pub fn f() { let p = \"rustc\".to_owned(); let _ = Command::new(&p); }\n";
    assert_eq!(kinds(FIXTURE_PATH, owned), [Kind::LiteralProgram]);
    let constant = "const GIT: &str = \"git\";\npub fn f() { let _ = Command::new(GIT); }\n";
    assert_eq!(kinds(FIXTURE_PATH, constant), [Kind::LiteralProgram]);
    let other_fn = "pub fn g() { let program = \"sh\"; }\n\
                    pub fn f(program: &std::path::Path) { let _ = Command::new(program); }\n";
    assert_eq!(
        kinds(FIXTURE_PATH, other_fn),
        Vec::<Kind>::new(),
        "a binding is resolved within its own fn only"
    );
}

#[test]
fn a_typed_or_absolute_program_is_admitted() {
    let typed = "pub fn f(tool: &ToolPath) { let _ = Command::new(tool.as_path()); }\n";
    assert_eq!(kinds(FIXTURE_PATH, typed), Vec::<Kind>::new());
    let field = "impl S { fn f(&self) { let _ = Command::new(&self.cargo); } }\n";
    assert_eq!(kinds(FIXTURE_PATH, field), Vec::<Kind>::new());
    let absolute = "pub fn f() { let _ = Command::new(\"/bin/ps\"); }\n";
    assert_eq!(kinds(FIXTURE_PATH, absolute), Vec::<Kind>::new());
}

#[test]
fn a_site_in_a_macro_body_is_refused() {
    let src = "pub fn f() { m!(std::env::split_paths(&p)); m!(Command::new(\"git\")); }\n";
    assert_eq!(
        kinds(FIXTURE_PATH, src),
        [Kind::PathWalk, Kind::LiteralProgram]
    );
}

#[test]
fn a_cfg_test_site_is_accepted_and_only_while_gated() {
    let src = "#[cfg(test)]\nfn f() { let _ = Command::new(\"git\"); \
               let _ = std::env::split_paths(\"\"); }\n";
    assert_eq!(kinds(FIXTURE_PATH, src), Vec::<Kind>::new());
    let ungated = src.replace("#[cfg(test)]", "");
    assert_eq!(
        kinds(FIXTURE_PATH, &ungated),
        [Kind::LiteralProgram, Kind::PathWalk]
    );
}

#[test]
fn an_unparseable_file_is_red() {
    assert!(scan_source(FIXTURE_PATH, "pub fn f( {").is_err());
}

/// A scanned root that cannot be listed is red, never an empty, green walk.
#[test]
fn an_unlistable_root_is_unjudged() {
    let missing = e2e_support::manifest_dir!().join("tool_path_scan/no-such-repository");
    let (files, unjudged) = production_files(&missing);
    assert!(files.is_empty(), "{files:?}");
    assert_eq!(unjudged.len(), ROOTS.len(), "{unjudged:?}");
}

#[test]
fn the_ratchet_refuses_new_and_stale_sites() {
    let site = Site {
        line: 1,
        kind: Kind::LiteralProgram,
        text: String::from("git"),
    };
    let found = BTreeMap::from([(String::from("a.rs"), vec![site.clone(), site])]);
    let exact = BTreeMap::from([(String::from("a.rs"), 2)]);
    assert!(ratchet_problems(&found, &exact).is_empty());
    let lower = BTreeMap::from([(String::from("a.rs"), 1)]);
    assert_eq!(ratchet_problems(&found, &lower).len(), 1, "over-count");
    let higher = BTreeMap::from([(String::from("a.rs"), 3)]);
    assert_eq!(ratchet_problems(&found, &higher).len(), 1, "under-count");
    let gone = BTreeMap::from([(String::from("a.rs"), 2), (String::from("b.rs"), 1)]);
    assert_eq!(ratchet_problems(&found, &gone).len(), 1, "stale line");
    assert!(pending_counts("a.rs 0").is_err(), "stale zero");
    assert!(pending_counts("a.rs 1\na.rs 1").is_err());
    assert!(pending_counts("a.rs").is_err());
    assert_eq!(
        pending_counts("# header\n\na.rs 2"),
        Ok(BTreeMap::from([(String::from("a.rs"), 2)]))
    );
}

/// Every skipped directory name is ignored by the repository `.gitignore`, so
/// the skip can hide no tracked source.
#[test]
fn every_skipped_dir_is_gitignored() {
    let gitignore = std::fs::read_to_string(e2e_support::manifest_dir!().join("../../.gitignore"))
        .expect(".gitignore reads");
    let patterns = gitignore.lines().map(str::trim).collect::<BTreeSet<_>>();
    for name in SKIPPED_DIRS {
        assert!(
            patterns.contains(format!("**/{name}").as_str())
                || patterns.contains(format!("**/{name}/").as_str()),
            "{name} is skipped but no `**/{name}` line of .gitignore ignores it"
        );
    }
}

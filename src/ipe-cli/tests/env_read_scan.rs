#![forbid(unsafe_code)]
//! Every operator environment variable is read through one typed registry key.
//!
//! A variable read by more than one site, or by a site that interprets the
//! text itself, drifts: two defaults, two grammars, a malformed value one site
//! refuses and another silently ignores. The runtime's registry
//! (`src/runtime/rust/src/env_registry/`, `env_grammar.rs`) is the one place a
//! variable is named, parsed and documented.
//!
//! The scan runs over every `.rs` file under `src/` and `tools/`, parsed with
//! `syn` through `panic_scan`, the front-end `tools/panic-scan` uses. Test code
//! is a `tests` directory, a `tests.rs` file, or an item whose `cfg` is
//! test-only by [`panic_scan::test_only_item_lines`]; every other line is
//! production. Outside the registry it refuses, in production code:
//!
//! 1. a string, byte-string or C-string literal holding an `IPE_[A-Z0-9_]+`
//!    token that is not an `EXCLUDED_NAMES` harness variable, a `concat!`
//!    being judged on the join of its literal arguments, and a doc attribute
//!    being prose, never a read;
//! 2. a `read_env_var`, `read_env_var_os`, `ipe_env::var` or `ipe_env::var_os`
//!    path, through any `use … as` rename of the accessor or of `ipe_env`,
//!    unless its first argument is a host variable literal ([`HOST_NAMES`]) or
//!    the file is on the program surface ([`PROGRAM_SURFACE`]), where a name
//!    the program chooses reaches the environment.
//!
//! Macro bodies are walked token by token under the same two rules. A file
//! that does not parse is red, never skipped.
//!
//! The sites not yet moved into the registry are held to
//! `env_read_scan/pending.txt`, a shrink-only ratchet: a file with more sites
//! than its line allows is red, and so is a line that allows more than the file
//! has.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Span, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprPath, Lit, Macro, Meta, UseTree};

/// The source roots scanned, relative to the repository root.
const ROOTS: &[&str] = &["src", "tools"];

/// Directory names never descended into, each a `**/<name>` line of the
/// repository `.gitignore` (build output and vendored JavaScript packages), so
/// no tracked source can sit under one. A dot-directory is likewise ignored
/// output (`.ipe`, `.ipe-cache`) or tool config, never a Rust module.
const SKIPPED_DIRS: &[&str] = &["target", "out", "node_modules"];

/// The registry: every path starting with one of these may name and read a
/// variable.
const REGISTRY: &[&str] = &[
    "src/runtime/rust/src/env_registry/",
    "src/runtime/rust/src/env_grammar.rs",
];

/// The program surface: files whose accessor calls read a name the Ipê
/// program chooses (`App.fromEnv`, `System.getenv`, the email provider
/// endpoints). Their literals are still judged.
const PROGRAM_SURFACE: &[&str] = &[
    "src/runtime/rust/src/app_config.rs",
    "src/runtime/rust/src/system.rs",
    "src/runtime/rust/src/email.rs",
];

/// The accessor fns a read is made through.
const ACCESSORS: &[&str] = &["read_env_var", "read_env_var_os"];

/// The audited environment module.
const ENV_MODULE: &str = "ipe_env";

/// The accessors of [`ENV_MODULE`].
const MODULE_ACCESSORS: &[&str] = &["var", "var_os"];

/// Host variables no Ipê registry owns; an accessor called on one of these
/// literals is not an operator read.
const HOST_NAMES: &[&str] = &[
    "PATH",
    "TERM",
    "COLORTERM",
    "NO_COLOR",
    "CI",
    "GITHUB_TOKEN",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "HOME",
    "SystemRoot",
    "DATABASE_URL",
];

/// The prefix of the Cargo build variables, all host variables.
const HOST_PREFIX: &str = "CARGO_";

/// The ratchet of sites not yet moved into the registry.
const PENDING: &str = include_str!("env_read_scan/pending.txt");

/// Which rule a site breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A literal naming a variable.
    Literal,
    /// An accessor path.
    Accessor,
}

/// One refused site in a file.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Site {
    /// 1-based line of the site's first token.
    line: usize,
    /// The rule it breaks.
    kind: Kind,
    /// The literal's value or the accessor's name, for the report.
    text: String,
}

/// Whether `name` is a host variable.
fn is_host(name: &str) -> bool {
    HOST_NAMES.contains(&name) || name.starts_with(HOST_PREFIX)
}

/// Whether `text` holds an `IPE_[A-Z0-9_]+` token outside `excluded`.
fn names_a_variable(text: &str, excluded: &[&str]) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find("IPE_") {
        let Some(after) = rest.get(at.saturating_add(4)..) else {
            return false;
        };
        let len = after
            .bytes()
            .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
            .count();
        let end = at.saturating_add(4).saturating_add(len);
        if len > 0
            && rest
                .get(at..end)
                .is_some_and(|token| !excluded.contains(&token))
        {
            return true;
        }
        let Some(next) = rest.get(end..) else {
            return false;
        };
        rest = next;
    }
    false
}

/// The 1-based line `span` starts on.
fn line_of(span: Span) -> usize {
    span.start().line
}

/// The value of a string, byte-string or C-string literal token.
fn literal_text(lit: &Lit) -> Option<String> {
    match lit {
        Lit::Str(s) => Some(s.value()),
        Lit::ByteStr(b) => Some(String::from_utf8_lossy(&b.value()).into_owned()),
        Lit::CStr(c) => Some(c.value().to_string_lossy().into_owned()),
        _ => None,
    }
}

/// The join of the top-level literal arguments of a `concat!`.
fn concat_join(tokens: &TokenStream) -> String {
    tokens
        .clone()
        .into_iter()
        .filter_map(|tree| match tree {
            TokenTree::Literal(lit) => literal_text(&Lit::new(lit)),
            _ => None,
        })
        .collect()
}

/// Whether `arg` is a host variable literal.
fn is_host_literal(arg: &Expr) -> bool {
    matches!(arg, Expr::Lit(lit) if matches!(&lit.lit, Lit::Str(s) if is_host(&s.value())))
}

/// Whether `tree` is the punctuation `ch`.
fn is_punct(tree: Option<&TokenTree>, ch: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

/// Whether `tree` is a parenthesised argument list whose first argument is
/// exactly a host variable literal.
fn is_host_call(tree: Option<&TokenTree>) -> bool {
    let Some(TokenTree::Group(group)) = tree else {
        return false;
    };
    if group.delimiter() != Delimiter::Parenthesis {
        return false;
    }
    let mut args = group.stream().into_iter();
    let Some(TokenTree::Literal(first)) = args.next() else {
        return false;
    };
    let Lit::Str(name) = Lit::new(first) else {
        return false;
    };
    let next = args.next();
    is_host(&name.value()) && (next.is_none() || is_punct(next.as_ref(), ','))
}

/// The accessor and module names in scope in one file, renames included.
struct Names {
    /// Bare accessor names.
    accessors: BTreeSet<String>,
    /// Names of the audited module.
    modules: BTreeSet<String>,
}

impl Names {
    /// The names a file sees, after every `use … as` rename in it.
    fn of(file: &syn::File) -> Self {
        let mut names = Self {
            accessors: ACCESSORS.iter().map(ToString::to_string).collect(),
            modules: BTreeSet::from([ENV_MODULE.to_owned()]),
        };
        names.visit_file(file);
        names
    }

    /// Record the renames under `tree`, whose parent path segment is `parent`.
    fn renames(&mut self, tree: &UseTree, parent: Option<&str>) {
        match tree {
            UseTree::Path(path) => {
                let segment = path.ident.unraw().to_string();
                self.renames(&path.tree, Some(&segment));
            }
            UseTree::Rename(rename) => {
                let name = rename.ident.unraw().to_string();
                let alias = rename.rename.unraw().to_string();
                let under_module = parent.is_some_and(|p| self.modules.contains(p));
                if self.accessors.contains(&name)
                    || (under_module && MODULE_ACCESSORS.contains(&name.as_str()))
                {
                    self.accessors.insert(alias);
                } else if self.modules.contains(&name) || (under_module && name == "self") {
                    self.modules.insert(alias);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.renames(item, parent);
                }
            }
            UseTree::Name(_) | UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for Names {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.renames(&item.tree, None);
    }
}

/// The refused sites of one parsed file.
struct Reads<'a> {
    /// The accessor and module names in scope.
    names: Names,
    /// Harness variables a literal may name.
    excluded: &'a [&'a str],
    /// The sites found so far.
    sites: Vec<Site>,
}

impl Reads<'_> {
    /// Record `text` at `span` when it names a variable.
    fn literal(&mut self, span: Span, text: &str) {
        if names_a_variable(text, self.excluded) {
            self.sites.push(Site {
                line: line_of(span),
                kind: Kind::Literal,
                text: text.chars().take(60).collect(),
            });
        }
    }

    /// Record an accessor named `text` at `span`.
    fn accessor(&mut self, span: Span, text: String) {
        self.sites.push(Site {
            line: line_of(span),
            kind: Kind::Accessor,
            text,
        });
    }

    /// Whether `path` names an accessor: its last segment is one, or its last
    /// two are the audited module and one of its accessors.
    fn is_accessor_path(&self, path: &syn::Path) -> bool {
        let mut segments = path.segments.iter().rev();
        let Some(last) = segments.next() else {
            return false;
        };
        let name = last.ident.unraw().to_string();
        if self.names.accessors.contains(&name) {
            return true;
        }
        MODULE_ACCESSORS.contains(&name.as_str())
            && segments.next().is_some_and(|parent| {
                self.names
                    .modules
                    .contains(&parent.ident.unraw().to_string())
            })
    }

    /// Judge a macro body token by token.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut at = 0usize;
        while let Some(tree) = trees.get(at) {
            match tree {
                TokenTree::Punct(p) if p.as_char() == '#' => {
                    let inner = is_punct(trees.get(at.saturating_add(1)), '!');
                    let group_at = at.saturating_add(if inner { 2 } else { 1 });
                    if let Some(TokenTree::Group(attr)) = trees.get(group_at)
                        && attr.delimiter() == Delimiter::Bracket
                    {
                        let is_doc = matches!(
                            attr.stream().into_iter().next(),
                            Some(TokenTree::Ident(ident)) if ident == "doc"
                        );
                        if !is_doc {
                            self.tokens(attr.stream());
                        }
                        at = group_at.saturating_add(1);
                        continue;
                    }
                }
                TokenTree::Ident(ident) => {
                    let name = ident.unraw().to_string();
                    if name == "concat"
                        && is_punct(trees.get(at.saturating_add(1)), '!')
                        && let Some(TokenTree::Group(args)) = trees.get(at.saturating_add(2))
                    {
                        self.literal(ident.span(), &concat_join(&args.stream()));
                        at = at.saturating_add(3);
                        continue;
                    }
                    if self.names.accessors.contains(&name) {
                        let previous = at.checked_sub(1).and_then(|p| trees.get(p));
                        let is_method_or_definition = is_punct(previous, '.')
                            || matches!(previous, Some(TokenTree::Ident(i)) if i == "fn");
                        if !is_method_or_definition
                            && !is_host_call(trees.get(at.saturating_add(1)))
                        {
                            self.accessor(ident.span(), name);
                        }
                        at = at.saturating_add(1);
                        continue;
                    }
                    if self.names.modules.contains(&name)
                        && is_punct(trees.get(at.saturating_add(1)), ':')
                        && is_punct(trees.get(at.saturating_add(2)), ':')
                        && let Some(TokenTree::Ident(function)) = trees.get(at.saturating_add(3))
                        && MODULE_ACCESSORS.contains(&function.unraw().to_string().as_str())
                    {
                        if !is_host_call(trees.get(at.saturating_add(4))) {
                            self.accessor(ident.span(), format!("{name}::{function}"));
                        }
                        at = at.saturating_add(4);
                        continue;
                    }
                }
                TokenTree::Literal(lit) => {
                    if let Some(text) = literal_text(&Lit::new(lit.clone())) {
                        self.literal(lit.span(), &text);
                    }
                }
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) => {}
            }
            at = at.saturating_add(1);
        }
    }
}

impl<'ast> Visit<'ast> for Reads<'_> {
    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        if attr.path().is_ident("doc") {
            return;
        }
        match &attr.meta {
            Meta::List(list) => self.tokens(list.tokens.clone()),
            Meta::NameValue(pair) => self.visit_expr(&pair.value),
            Meta::Path(_) => {}
        }
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.literal(lit.span(), &lit.value());
    }

    fn visit_lit_byte_str(&mut self, lit: &'ast syn::LitByteStr) {
        self.literal(lit.span(), &String::from_utf8_lossy(&lit.value()));
    }

    fn visit_lit_cstr(&mut self, lit: &'ast syn::LitCStr) {
        self.literal(lit.span(), &lit.value().to_string_lossy());
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let span = mac
            .path
            .segments
            .first()
            .map_or_else(Span::call_site, |segment| segment.ident.span());
        if mac.path.is_ident("concat") {
            self.literal(span, &concat_join(&mac.tokens));
        } else {
            self.tokens(mac.tokens.clone());
        }
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = &*call.func
            && self.is_accessor_path(&path.path)
            && call.args.first().is_some_and(is_host_literal)
        {
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if self.is_accessor_path(&path.path) {
            let span = path
                .path
                .segments
                .first()
                .map_or_else(Span::call_site, |segment| segment.ident.span());
            let text = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            self.accessor(span, text);
            return;
        }
        visit::visit_expr_path(self, path);
    }
}

/// The `EXCLUDED_NAMES` a literal may name outside the registry: every one
/// that is not also a registry entry's name. An internal registry entry is
/// excluded from the operator docs, but its name is still spelled only by its
/// key, so the docs exclusion never exempts it here.
fn harness_names() -> Vec<&'static str> {
    ipe_docs::env_vars::EXCLUDED_NAMES
        .iter()
        .copied()
        .filter(|name| {
            !ipe_runtime_rust::env_registry::registry().any(|entry| entry.name() == *name)
        })
        .collect()
}

/// The refused production sites of the file at `rel` holding `src`.
///
/// # Errors
///
/// A message naming `rel` when it does not parse or is over a parse ceiling.
fn scan_source(rel: &str, src: &str) -> Result<Vec<Site>, String> {
    if REGISTRY.iter().any(|prefix| rel.starts_with(prefix)) {
        return Ok(Vec::new());
    }
    let test_lines = panic_scan::test_only_item_lines(src)
        .map_err(|e| format!("{rel}: does not parse, so it cannot be judged: {e}"))?;
    let excluded = harness_names();
    let excluded = excluded.as_slice();
    let sites = panic_scan::with_parsed(src, |file| {
        let mut reads = Reads {
            names: Names::of(file),
            excluded,
            sites: Vec::new(),
        };
        reads.visit_file(file);
        reads.sites
    })
    .map_err(|e| format!("{rel}: does not parse, so it cannot be judged: {e}"))?;
    let program_surface = PROGRAM_SURFACE.contains(&rel);
    Ok(sites
        .into_iter()
        .filter(|site| !(program_surface && site.kind == Kind::Accessor))
        .filter(|site| !test_lines.iter().any(|span| span.contains(&site.line)))
        .collect())
}

/// Every production `.rs` file under the scanned roots of `repo`, as its path
/// relative to `repo` with `/` separators.
///
/// A `tests` directory or `tests.rs` file is skipped only once its test-only
/// premise is confirmed on disk ([`panic_scan::is_verified_test_path`]); an
/// ungated `mod tests;` is production and scanned.
///
/// # Errors
///
/// A message naming the path when a directory cannot be listed, an entry's
/// type cannot be read, or an entry is a symlinked directory the walk does not
/// follow: a tree the walk cannot see into cannot be judged clean.
fn production_files(repo: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = ROOTS.iter().map(|root| repo.join(root)).collect();
    while let Some(dir) = pending.pop() {
        let unlisted = |e: std::io::Error| format!("{}: cannot be listed: {e}", dir.display());
        for entry in std::fs::read_dir(&dir).map_err(unlisted)? {
            let entry = entry.map_err(unlisted)?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| format!("{}: type cannot be read: {e}", path.display()))?;
            if kind.is_symlink() && path.is_dir() {
                return Err(format!(
                    "{}: a symlinked directory is not followed, so it cannot be judged",
                    path.display()
                ));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if kind.is_dir() {
                if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_str()) {
                    pending.push(path);
                }
                continue;
            }
            let Ok(rel) = path.strip_prefix(repo) else {
                return Err(format!(
                    "{}: lies outside {}",
                    path.display(),
                    repo.display()
                ));
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
    Ok(found)
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
                "{rel}: {} site(s), pending.txt allows {limit}; read the variable through a \
                 registry key in `env_registry`:\n{listed}",
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
fn every_operator_variable_is_read_through_the_registry() {
    let repo = e2e_support::manifest_dir!().join("../..");
    let files = production_files(&repo).expect("the production tree is walkable");
    assert!(
        files.len() > 100,
        "only {} production files found under {}",
        files.len(),
        repo.display()
    );
    let allowed = pending_counts(PENDING).expect("pending.txt parses");

    let mut found = BTreeMap::new();
    let mut unjudged = Vec::new();
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

/// A fixture file under `env_read_scan/fixtures/`.
macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("env_read_scan/fixtures/", $name, ".rs.txt"))
    };
}

/// The path a fixture is judged at: production, outside the registry and the
/// program surface.
const FIXTURE_PATH: &str = "src/fixture.rs";

/// The kinds of the sites the scan finds in `src` at `rel`.
fn kinds(rel: &str, src: &str) -> Vec<Kind> {
    scan_source(rel, src)
        .expect("fixture parses")
        .into_iter()
        .map(|site| site.kind)
        .collect()
}

#[test]
fn a_clean_file_has_no_site() {
    assert_eq!(kinds(FIXTURE_PATH, fixture!("clean")), Vec::<Kind>::new());
}

#[test]
fn a_literal_in_a_production_fn_is_refused() {
    let src = fixture!("literal_in_fn");
    assert_eq!(kinds(FIXTURE_PATH, src), [Kind::Literal]);
    assert_eq!(
        kinds("src/runtime/rust/src/env_registry/web.rs", src),
        Vec::<Kind>::new(),
        "the registry names variables"
    );
    assert_eq!(
        kinds("src/runtime/rust/src/system.rs", src),
        [Kind::Literal],
        "the program surface is exempt from the accessor rule only"
    );
}

#[test]
fn a_const_alias_is_refused_by_its_literal() {
    assert_eq!(
        kinds(FIXTURE_PATH, fixture!("const_alias")),
        [Kind::Literal]
    );
}

#[test]
fn a_renamed_accessor_is_refused() {
    let src = fixture!("renamed_accessor");
    assert_eq!(
        kinds(FIXTURE_PATH, src),
        [Kind::Accessor, Kind::Accessor, Kind::Accessor]
    );
    assert_eq!(
        kinds("src/runtime/rust/src/app_config.rs", src),
        Vec::<Kind>::new(),
        "the program surface reads names the program chooses"
    );
}

#[test]
fn a_concat_literal_is_judged_on_its_join() {
    assert_eq!(
        kinds(FIXTURE_PATH, fixture!("concat_literal")),
        [Kind::Literal]
    );
}

#[test]
fn a_read_in_a_macro_body_is_refused() {
    assert_eq!(
        kinds(FIXTURE_PATH, fixture!("macro_body")),
        [Kind::Accessor, Kind::Literal]
    );
}

#[test]
fn a_cfg_test_read_is_accepted_and_only_while_gated() {
    let src = fixture!("cfg_test_read");
    assert_eq!(kinds(FIXTURE_PATH, src), Vec::<Kind>::new());
    let ungated = src.replace("#[cfg(test)]", "");
    assert_eq!(
        kinds(FIXTURE_PATH, &ungated),
        [Kind::Accessor, Kind::Literal]
    );
}

#[test]
fn an_unparseable_file_is_red() {
    assert!(scan_source(FIXTURE_PATH, fixture!("unparseable")).is_err());
}

#[test]
fn a_variable_token_needs_a_name_outside_the_harness_set() {
    assert!(names_a_variable("set IPE_WEB_PORT=1", &[]));
    assert!(!names_a_variable("IPE_WEB_PORT", &["IPE_WEB_PORT"]));
    assert!(!names_a_variable("IPE_ alone, ipe_web_port", &[]));
    assert!(names_a_variable(
        "IPE_WEB_PORT IPE_SERVER_PORT",
        &["IPE_WEB_PORT"]
    ));
}

#[test]
fn the_ratchet_refuses_new_and_stale_sites() {
    let site = Site {
        line: 1,
        kind: Kind::Accessor,
        text: String::from("read_env_var"),
    };
    let found = BTreeMap::from([(String::from("a.rs"), vec![site.clone(), site])]);
    let exact = BTreeMap::from([(String::from("a.rs"), 2)]);
    assert!(ratchet_problems(&found, &exact).is_empty());
    let lower = BTreeMap::from([(String::from("a.rs"), 1)]);
    assert_eq!(ratchet_problems(&found, &lower).len(), 1);
    let higher = BTreeMap::from([(String::from("a.rs"), 3)]);
    assert_eq!(ratchet_problems(&found, &higher).len(), 1);
    let gone = BTreeMap::from([(String::from("a.rs"), 2), (String::from("b.rs"), 1)]);
    assert_eq!(ratchet_problems(&found, &gone).len(), 1);
    assert!(pending_counts("a.rs 0").is_err());
    assert!(pending_counts("a.rs 1\na.rs 1").is_err());
    assert!(pending_counts("a.rs").is_err());
    assert_eq!(
        pending_counts("# header\n\na.rs 2"),
        Ok(BTreeMap::from([(String::from("a.rs"), 2)]))
    );
}

/// A docs exclusion exempts a harness name, never a registry entry's name:
/// the internal relocation port is excluded from the operator docs but is
/// still spelled only by its key.
#[test]
fn an_excluded_name_that_is_registered_is_still_refused() {
    let named = |name: &str| format!("pub fn f() -> &'static str {{ \"{name}\" }}\n");
    assert_eq!(
        kinds(FIXTURE_PATH, &named("IPE_INTERNAL_LISTEN_PORT")),
        [Kind::Literal]
    );
    assert_eq!(kinds(FIXTURE_PATH, &named("IPE_E2E")), Vec::<Kind>::new());
    let harness = harness_names();
    assert!(
        !harness.contains(&"IPE_INTERNAL_LISTEN_PORT"),
        "{harness:?}"
    );
    assert!(harness.contains(&"IPE_E2E"), "{harness:?}");
}

/// A fresh tree holding `files` (path relative to the tree, contents).
fn tree(label: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = ipe_test_temp::temp_root()
        .join(format!("ipe_env_read_scan_{label}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, text) in files {
        let path = root.join(rel);
        let parent = path.parent().expect("a tree file has a parent");
        std::fs::create_dir_all(parent).expect("tree dir is created");
        std::fs::write(&path, text).expect("tree file is written");
    }
    root
}

/// The walk scans what only looks like test code or tool input: an ungated
/// `mod tests;` body and a module under a directory named `fixtures`. A test
/// module gated behind `#[cfg(test)]` and ignored build output are skipped.
#[test]
fn the_walk_skips_only_confirmed_test_code_and_ignored_output() {
    let root = tree(
        "walk",
        &[
            ("src/lib.rs", "pub mod tests;\npub mod fixtures;\n"),
            ("src/tests/mod.rs", "pub fn f() {}\n"),
            ("src/fixtures/mod.rs", "pub fn f() {}\n"),
            ("src/out/emitted.rs", "pub fn f() {}\n"),
            ("tools/gated/lib.rs", "#[cfg(test)]\nmod tests;\n"),
            ("tools/gated/tests/mod.rs", "fn f() {}\n"),
        ],
    );
    let found = production_files(&root);
    let _ = std::fs::remove_dir_all(&root);
    let rels = found
        .expect("the tree is walkable")
        .into_iter()
        .map(|(rel, _)| rel)
        .collect::<Vec<_>>();
    assert_eq!(
        rels,
        [
            "src/fixtures/mod.rs",
            "src/lib.rs",
            "src/tests/mod.rs",
            "tools/gated/lib.rs"
        ]
    );
}

/// A root the walk cannot list, and a symlinked directory it does not follow,
/// are red: an unseen tree is never judged clean.
#[test]
fn an_unwalkable_tree_is_red() {
    let root = tree("unwalkable", &[("src/lib.rs", "pub fn f() {}\n")]);
    let missing_root = production_files(&root);
    #[cfg(unix)]
    let linked = {
        std::fs::create_dir_all(root.join("tools")).expect("tools dir is created");
        std::os::unix::fs::symlink(root.join("src"), root.join("tools/linked"))
            .expect("symlink is created");
        production_files(&root)
    };
    let _ = std::fs::remove_dir_all(&root);
    assert!(missing_root.is_err(), "{missing_root:?}");
    #[cfg(unix)]
    assert!(
        linked
            .as_ref()
            .is_err_and(|e| e.contains("symlinked directory")),
        "{linked:?}"
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

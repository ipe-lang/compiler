#![forbid(unsafe_code)]
//! Pins that every command resolves its runtime through one resolver.
//!
//! The vendored module tree is looked up only by `resolve_runtime`, and
//! `resolve_runtime` is called only by `resolve_vendored_runtime_dir`, which
//! every emitting command (`ipe dev build`/`run`/`watch`, `ipe test`,
//! `ipe release`, eject, desktop) reaches with the `RuntimeEmit` of the very
//! options its emit runs with. The linked runtime crate is resolved by
//! `runtime_embed::resolve`/`resolve_for` only in the compile core, the watch
//! loop, `ipe health` and a failure message, so a build and its health check
//! read one chain. This scan parses the non-test code of the CLI and refuses
//! each of those spellings outside the (file, function) sites admitted below,
//! macro bodies included, and refuses any second name for them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// The source tree the scan judges, relative to the repository root.
const TREE: &str = "src/ipe-cli/src";

/// The module that defines the linked-runtime resolvers and calls them unqualified.
const EMBED_MODULE: &str = "src/ipe-cli/src/runtime_embed.rs";

/// The vendored-tree lookups, guarded by their bare name.
const BARE: &[&str] = &["resolve_runtime", "resolve_runtime_src"];

/// The linked-runtime resolvers, guarded as `runtime_embed::<name>`.
const EMBED_RESOLVERS: &[&str] = &["resolve", "resolve_for"];

/// The module the linked-runtime resolvers live in.
const EMBED: &str = "runtime_embed";

/// Each admitted site: what is spelled, the file, the function, and how often.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    (
        "resolve_runtime_src",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "resolve_runtime",
        1,
    ),
    (
        "resolve_runtime",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "resolve_vendored_runtime_dir",
        1,
    ),
    (
        "runtime_embed::resolve_for",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "compile_source_set_here",
        1,
    ),
    (
        "runtime_embed::resolve",
        "src/ipe-cli/src/health.rs",
        "check_runtime",
        1,
    ),
    (
        "runtime_embed::resolve",
        "src/ipe-cli/src/watch.rs",
        "run_inner",
        1,
    ),
    (
        "runtime_embed::resolve",
        "src/ipe-cli/src/driver/commands.rs",
        "runtime_context_for_message",
        1,
    ),
];

/// Whether `meta` holds only under `cfg(test)`.
fn test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(test_only)
            } else if list.path.is_ident("any") {
                !nested.is_empty() && nested.iter().all(test_only)
            } else {
                false
            }
        }
        Meta::NameValue(_) => false,
    }
}

/// Whether `attrs` compile the item only under `cfg(test)`, or mark a test.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .meta
                    .require_list()
                    .ok()
                    .and_then(|list| syn::parse2::<Meta>(list.tokens.clone()).ok())
                    .is_some_and(|meta| test_only(&meta)))
    })
}

/// The attributes of `item`; none for an item kind syn adds later.
fn item_attrs(item: &syn::Item) -> &[Attribute] {
    match item {
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        _ => &[],
    }
}

/// The guarded label a path ending in `names` spells, if any.
fn label(names: &[String]) -> Option<String> {
    if let [.., module, member] = names
        && module == EMBED
        && EMBED_RESOLVERS.contains(&member.as_str())
    {
        return Some(format!("{EMBED}::{member}"));
    }
    names
        .last()
        .filter(|last| BARE.contains(&last.as_str()))
        .cloned()
}

/// What the scan found in one source.
#[derive(Default)]
struct Scan {
    /// The enclosing function names, innermost last.
    fns: Vec<String>,
    /// The `use` path segments the visitor is under, outermost first.
    use_prefix: Vec<String>,
    /// Each guarded spelling met, with the function it sits in, counted.
    sites: BTreeMap<(String, String), usize>,
    /// Each second name for a guarded resolver, with the function it sits in.
    aliases: Vec<(String, String)>,
    /// The out-of-line `cfg(test)` modules this source declares.
    test_mods: Vec<String>,
}

impl Scan {
    /// The function the visitor is in, or `<file>` at item level.
    fn site(&self) -> String {
        self.fns
            .last()
            .cloned()
            .unwrap_or_else(|| "<file>".to_owned())
    }

    /// Count the path `names` when it spells a guarded resolver.
    fn path(&mut self, names: &[String]) {
        if let Some(what) = label(names) {
            let site = self.site();
            *self.sites.entry((site, what)).or_insert(0) += 1;
        }
    }

    /// Record a second name for a guarded resolver.
    fn alias(&mut self, what: String) {
        let site = self.site();
        self.aliases.push((site, what));
    }

    /// Count every guarded path a macro body spells.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut path: Vec<String> = Vec::new();
        let mut colons = 0_usize;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    if colons != 2 {
                        path.clear();
                    }
                    colons = 0;
                    path.push(ident.to_string());
                    self.path(&path);
                }
                TokenTree::Punct(punct) if punct.as_char() == ':' => colons += 1,
                TokenTree::Group(group) => {
                    self.tokens(group.stream());
                    path.clear();
                    colons = 0;
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {
                    path.clear();
                    colons = 0;
                }
            }
        }
    }

    /// Run `walk` inside the function `name`.
    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.fns.push(name);
        walk(self);
        self.fns.pop();
    }

    /// Whether the `use` path being walked names the linked-runtime module.
    fn under_embed(&self) -> bool {
        self.use_prefix.last().is_some_and(|last| last == EMBED)
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if is_test_only(item_attrs(item)) {
            if let syn::Item::Mod(module) = item
                && module.content.is_none()
            {
                self.test_mods.push(module.ident.to_string());
            }
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within(item.sig.ident.to_string(), |scan| {
            visit::visit_item_fn(scan, item);
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_only(&item.attrs) {
            return;
        }
        self.within(item.sig.ident.to_string(), |scan| {
            visit::visit_impl_item_fn(scan, item);
        });
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        let names: Vec<String> = expr
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.path(&names);
        visit::visit_expr_path(self, expr);
    }

    fn visit_use_path(&mut self, path: &'ast syn::UsePath) {
        self.use_prefix.push(path.ident.to_string());
        visit::visit_use_path(self, path);
        self.use_prefix.pop();
    }

    fn visit_use_name(&mut self, name: &'ast syn::UseName) {
        if self.under_embed() && EMBED_RESOLVERS.iter().any(|r| name.ident == r) {
            self.alias(format!("use {EMBED}::{}", name.ident));
        }
        visit::visit_use_name(self, name);
    }

    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        // `runtime_embed::{self as e}` names the module itself under `e`.
        let guarded = rename.ident == EMBED
            || BARE.iter().any(|name| rename.ident == name)
            || (self.under_embed()
                && (rename.ident == "self" || EMBED_RESOLVERS.iter().any(|r| rename.ident == r)));
        if guarded {
            self.alias(format!("use {} as {}", rename.ident, rename.rename));
        }
        visit::visit_use_rename(self, rename);
    }

    fn visit_use_glob(&mut self, glob: &'ast syn::UseGlob) {
        if self.under_embed() {
            self.alias(format!("use {EMBED}::*"));
        }
        visit::visit_use_glob(self, glob);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Scan `source`.
fn scan(source: &str) -> Result<Scan, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse: {e}"))?;
    let mut found = Scan::default();
    found.visit_file(&file);
    Ok(found)
}

/// The refusals of `found` (keyed by file) against [`ADMITTED`], one line each.
fn refusals(found: &BTreeMap<String, Scan>) -> Vec<String> {
    let mut seen: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    let mut out = Vec::new();
    for (rel, scan) in found {
        for ((site, what), count) in &scan.sites {
            seen.insert((what.clone(), rel.clone(), site.clone()), *count);
        }
        if rel != EMBED_MODULE {
            for (site, what) in &scan.aliases {
                out.push(format!(
                    "{rel}: `{what}` in `{site}`: a second name hides a site from this scan"
                ));
            }
        }
    }
    for ((what, rel, site), count) in &seen {
        let admitted = ADMITTED
            .iter()
            .find(|(w, r, s, _)| w == what && r == rel && s == site)
            .map_or(0, |(_, _, _, n)| *n);
        if *count != admitted {
            out.push(format!(
                "{rel}: `{what}` {count}x in `{site}` (admitted {admitted}x)"
            ));
        }
    }
    for (what, rel, site, admitted) in ADMITTED {
        let key = ((*what).to_owned(), (*rel).to_owned(), (*site).to_owned());
        if found.contains_key(*rel) && !seen.contains_key(&key) {
            out.push(format!(
                "{rel}: `{what}` is admitted {admitted}x in `{site}` but never met"
            ));
        }
    }
    out
}

/// The directory the out-of-line child modules of the source at `file` live in.
fn child_dir(file: &Path) -> PathBuf {
    let parent = file.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    match file.file_name().and_then(|name| name.to_str()) {
        Some("mod.rs" | "lib.rs" | "main.rs") => parent,
        _ => file.with_extension(""),
    }
}

/// The repository root.
fn repo_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest.clone(), Path::to_path_buf)
}

/// Scan every non-test source of [`TREE`], keyed by its path from the root.
///
/// An out-of-line `cfg(test)` module may sort before the file declaring it, so
/// every file is scanned first and the test modules are dropped after.
fn scan_tree() -> Result<BTreeMap<String, Scan>, String> {
    let root = repo_root();
    let files = panic_scan::rust_sources(&root.join(TREE), panic_scan::Want::RustFiles)
        .map_err(|e| format!("{TREE}: {e}"))?;
    let mut scanned = Vec::new();
    for file in files {
        let source =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let found = scan(&source).map_err(|e| format!("{}: {e}", file.display()))?;
        scanned.push((file, found));
    }
    let mut skipped: Vec<PathBuf> = Vec::new();
    for (file, found) in &scanned {
        let dir = child_dir(file);
        for name in &found.test_mods {
            skipped.push(dir.join(format!("{name}.rs")));
            skipped.push(dir.join(name));
        }
    }
    let mut out = BTreeMap::new();
    for (file, found) in scanned {
        if skipped.iter().any(|skip| file.starts_with(skip)) {
            continue;
        }
        let rel = file
            .strip_prefix(&root)
            .map_err(|e| format!("{}: {e}", file.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        out.insert(rel, found);
    }
    Ok(out)
}

/// A planted source, scanned as the file `rel`.
fn planted(rel: &str, source: &str) -> Result<Vec<String>, String> {
    let mut found = BTreeMap::new();
    found.insert(rel.to_owned(), scan(source)?);
    Ok(refusals(&found))
}

/// Every runtime resolver is reached only at its admitted sites.
#[test]
fn runtime_resolvers_are_reached_only_at_admitted_sites() -> Result<(), String> {
    let found = scan_tree()?;
    let mut refused = refusals(&found);
    for (_, rel, _, _) in ADMITTED {
        if !found.contains_key(*rel) {
            refused.push(format!("{rel}: an admitted file is not scanned"));
        }
    }
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    Ok(())
}

/// A second resolver, a second caller, or a second name is refused.
#[test]
fn a_planted_resolver_site_is_refused() -> Result<(), String> {
    let pipeline = "src/ipe-cli/src/driver/build_pipeline.rs";
    let pkg = "src/ipe-cli/src/driver/commands_pkg.rs";
    let cases = [
        // The test runner looking the vendored tree up by hand.
        (
            pkg,
            "fn run_project_tests_with() { let r = resolve_runtime()?; }\n",
        ),
        (
            pkg,
            "fn other() { let r = super::build_pipeline::resolve_runtime(); }\n",
        ),
        (pkg, "fn other() { let f = resolve_runtime; }\n"),
        (pkg, "fn other() { go(m!(resolve_runtime())); }\n"),
        // A second vendored-tree lookup beside the one resolver.
        (
            pkg,
            "fn other() { ipe_env::artifact::resolve_runtime_src(o, c); }\n",
        ),
        // The admitted pipeline shape with one lookup too many: only the
        // count can refuse it, so the case is not met by a missing site.
        (
            pipeline,
            "fn resolve_runtime() { resolve_runtime_src(a, b); resolve_runtime_src(a, b); }\n\
             fn resolve_vendored_runtime_dir() { resolve_runtime(); }\n\
             fn compile_source_set_here() { runtime_embed::resolve_for(o); }\n",
        ),
        // A second linked-runtime caller.
        (pkg, "fn other() { crate::runtime_embed::resolve(); }\n"),
        (pkg, "fn other() { runtime_embed::resolve_for(o); }\n"),
        (pkg, "fn other() { m!(crate::runtime_embed::resolve()); }\n"),
        // Second names.
        (pkg, "use crate::runtime_embed as embedded;\n"),
        (pkg, "use crate::runtime_embed::{self as embedded};\n"),
        (pkg, "use crate::runtime_embed::{resolve};\n"),
        (pkg, "use crate::runtime_embed::resolve_for as linked;\n"),
        (pkg, "use crate::runtime_embed::*;\n"),
        (pkg, "use super::resolve_runtime as vendored;\n"),
    ];
    for (rel, source) in cases {
        let refused = planted(rel, source)?;
        assert!(!refused.is_empty(), "{source} must be refused");
    }
    Ok(())
}

/// The admitted sites themselves pass, and a test-only caller is not judged.
#[test]
fn the_admitted_shape_passes() -> Result<(), String> {
    let pipeline = "src/ipe-cli/src/driver/build_pipeline.rs";
    let source = "use super::resolve_vendored_runtime_dir;\n\
                  fn resolve_runtime() { ipe_env::artifact::resolve_runtime_src(o, c); }\n\
                  fn resolve_vendored_runtime_dir() { resolve_runtime(); }\n\
                  fn compile_source_set_here() { runtime_embed::resolve_for(o); }\n\
                  #[cfg(test)]\nmod tests { fn t() { resolve_runtime(); } }\n\
                  #[test]\nfn direct() { resolve_runtime(); }\n";
    let refused = planted(pipeline, source)?;
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    Ok(())
}

#![forbid(unsafe_code)]
//! Pins that the runtime a command builds against is chosen in one module.
//!
//! `IPE_RUNTIME_DIR` is read only by `RuntimeSource::resolve` and
//! `IPE_RUNTIME_VENDORED` only by `RuntimeEmit::from_env`, both in
//! `runtime_embed.rs`; each command reaches those two readers at the admitted
//! sites below. Across the CLI, the test harness and the golden regenerator,
//! no other code names either variable, no runtime locator walks ancestors
//! without the ceiling, reads the current directory or builds an empty path,
//! and no retired resolver name is defined, called or imported. This scan
//! parses the non-test code of those trees, macro bodies included, and refuses
//! every guarded spelling outside its admitted (file, function) sites, plus
//! any second name for a guarded item.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// The source trees the scan judges, relative to the repository root.
const TREES: &[&str] = &[
    "src/ipe-cli/src",
    "tools/e2e-support/src",
    "tools/regen-goldens/src",
];

/// The one module that reads the runtime variables and locates a runtime.
const EMBED_MODULE: &str = "src/ipe-cli/src/runtime_embed.rs";

/// The module name of [`EMBED_MODULE`].
const EMBED: &str = "runtime_embed";

/// The runtime variables, as the literal that names each.
const VAR_LITERALS: &[&str] = &["IPE_RUNTIME_DIR", "IPE_RUNTIME_VENDORED"];

/// The constants that carry the runtime variable names.
const VAR_CONSTS: &[&str] = &["RUNTIME_DIR_VAR", "RUNTIME_VENDORED_VAR"];

/// The two readers, guarded as `<type>::<fn>`.
const READERS: &[(&str, &str)] = &[("RuntimeSource", "resolve"), ("RuntimeEmit", "from_env")];

/// The types whose second name would hide a reader call.
const READER_TYPES: &[&str] = &["RuntimeSource", "RuntimeEmit"];

/// Retired runtime resolvers: never defined, called or imported again.
const RETIRED: &[&str] = &[
    "materialize",
    "resolve_in_repo",
    "resolve_runtime_src",
    "runtime_dep_from_env",
    "resolve_runtime",
    "resolve_vendored_runtime_dir",
];

/// The harness locator: walks up from an anchor to the checkout's runtime
/// tree, so only the harness's `require_runtime` may reach it.
const HARNESS_LOCATOR: &str = "in_repo_runtime_src";

/// The harness module that anchors the [`HARNESS_LOCATOR`] walk.
const HARNESS: &str = "tools/e2e-support/src/bin.rs";

/// The gate's runtime admission: the compile core hands its emit only the
/// runtime the options' origin admits, so a gate never carries an override.
const ADMISSION: &str = "admitted_runtime";

/// The label of a zero-argument `ancestors()` walk in a runtime locator.
const ANCESTORS: &str = "ancestors() in a runtime locator";

/// The label of a current-directory read in a runtime locator.
const CURRENT_DIR: &str = "current_dir in a runtime locator";

/// The label of an empty path built in a runtime locator.
const EMPTY_PATH: &str = "an empty PathBuf in a runtime locator";

/// The build entry points' module.
const PIPELINE: &str = "src/ipe-cli/src/driver/build_pipeline.rs";

/// The command bodies' module.
const COMMANDS: &str = "src/ipe-cli/src/driver/commands.rs";

/// The health check's module.
const HEALTH: &str = "src/ipe-cli/src/health.rs";

/// Each admitted site: what is spelled, the file, the function, and how often.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    (
        "RuntimeSource::resolve",
        PIPELINE,
        "build_with_options_into",
        1,
    ),
    (
        "RuntimeSource::resolve",
        PIPELINE,
        "build_loose_file_into",
        1,
    ),
    ("RuntimeSource::resolve", PIPELINE, "build_test_into", 1),
    ("RuntimeSource::resolve", PIPELINE, "build_project_into", 1),
    ("RuntimeSource::resolve", COMMANDS, "run_watch", 1),
    ("RuntimeSource::resolve", COMMANDS, "run_build_body", 1),
    ("RuntimeSource::resolve", COMMANDS, "run_eject", 1),
    ("RuntimeSource::resolve", COMMANDS, "release_pipeline", 2),
    ("RuntimeSource::resolve", COMMANDS, "run_run_with_args", 1),
    (
        "RuntimeSource::resolve",
        "src/ipe-cli/src/driver/commands_pkg.rs",
        "emit_desktop",
        1,
    ),
    ("RuntimeSource::resolve", HEALTH, "check_runtime", 1),
    ("RuntimeEmit::from_env", PIPELINE, "from_env", 1),
    ("RuntimeEmit::from_env", COMMANDS, "run_watch", 1),
    ("RuntimeEmit::from_env", COMMANDS, "run_build_body", 1),
    ("RuntimeEmit::from_env", COMMANDS, "release_pipeline", 2),
    ("RuntimeEmit::from_env", COMMANDS, "run_run_with_args", 1),
    ("\"IPE_RUNTIME_DIR\"", EMBED_MODULE, "<file>", 1),
    ("\"IPE_RUNTIME_VENDORED\"", EMBED_MODULE, "<file>", 1),
    ("RUNTIME_DIR_VAR", EMBED_MODULE, "resolve", 1),
    ("RUNTIME_VENDORED_VAR", EMBED_MODULE, "from_env", 1),
    ("RUNTIME_VENDORED_VAR", EMBED_MODULE, "parse", 1),
    (ANCESTORS, EMBED_MODULE, "ancestors", 1),
    (HARNESS_LOCATOR, HARNESS, "<file>", 1),
    (HARNESS_LOCATOR, HARNESS, "require_runtime", 1),
    (ADMISSION, PIPELINE, "compile_source_set_here", 1),
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

/// What the scan found in one source.
#[derive(Default)]
struct Scan {
    /// Whether the source is [`EMBED_MODULE`], where every function locates.
    embed: bool,
    /// The enclosing function names, innermost last.
    fns: Vec<String>,
    /// The `use` path segments the visitor is under, outermost first.
    use_prefix: Vec<String>,
    /// Each guarded spelling met, with the function it sits in, counted.
    sites: BTreeMap<(String, String), usize>,
    /// Each second name for a guarded item, with the function it sits in.
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

    /// Whether the visitor is inside a runtime locator.
    fn in_locator(&self) -> bool {
        self.embed || self.fns.iter().any(|name| name.contains("runtime"))
    }

    /// Count one guarded spelling at the current site.
    fn met(&mut self, what: String) {
        let site = self.site();
        *self.sites.entry((site, what)).or_insert(0) += 1;
    }

    /// Count the path `names` when it spells a guarded item.
    fn path(&mut self, names: &[String]) {
        let Some(last) = names.last() else {
            return;
        };
        if VAR_CONSTS.contains(&last.as_str())
            || RETIRED.contains(&last.as_str())
            || last == HARNESS_LOCATOR
        {
            self.met(last.clone());
        }
        if let [.., owner, member] = names {
            if READERS.iter().any(|(t, f)| owner == t && member == f) {
                self.met(format!("{owner}::{member}"));
            }
            if self.in_locator() && owner == "PathBuf" && (member == "new" || member == "default") {
                self.met(EMPTY_PATH.to_owned());
            }
        }
        if self.in_locator() && last == "current_dir" {
            self.met(CURRENT_DIR.to_owned());
        }
    }

    /// Count a string literal naming a runtime variable.
    fn literal(&mut self, value: &str) {
        if VAR_LITERALS.contains(&value) {
            self.met(format!("\"{value}\""));
        }
    }

    /// Count a method call `.name(..)` taking `args` arguments.
    fn method(&mut self, name: &str, args: usize) {
        if name == ADMISSION {
            self.met(ADMISSION.to_owned());
        }
        if !self.in_locator() {
            return;
        }
        if name == "ancestors" && args == 0 {
            self.met(ANCESTORS.to_owned());
        }
        if name == "current_dir" {
            self.met(CURRENT_DIR.to_owned());
        }
    }

    /// Record a second name for a guarded item.
    fn alias(&mut self, what: String) {
        let site = self.site();
        self.aliases.push((site, what));
    }

    /// Count every guarded spelling a macro body holds.
    ///
    /// A method named in a macro body is judged as if it took no argument,
    /// the strict reading: its argument list is not parsed.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut path: Vec<String> = Vec::new();
        let mut colons = 0_usize;
        let mut dot = false;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    if colons != 2 {
                        path.clear();
                    }
                    colons = 0;
                    let name = ident.to_string();
                    if dot {
                        self.method(&name, 0);
                    }
                    dot = false;
                    path.push(name);
                    self.path(&path);
                }
                TokenTree::Punct(punct) if punct.as_char() == ':' => colons += 1,
                TokenTree::Punct(punct) => {
                    dot = punct.as_char() == '.';
                    path.clear();
                    colons = 0;
                }
                TokenTree::Group(group) => {
                    self.tokens(group.stream());
                    path.clear();
                    colons = 0;
                    dot = false;
                }
                TokenTree::Literal(literal) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                        self.literal(&text.value());
                    }
                    path.clear();
                    colons = 0;
                    dot = false;
                }
            }
        }
    }

    /// Run `walk` inside the function `name`, counting a retired definition.
    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        if RETIRED.contains(&name.as_str()) {
            self.met(format!("fn {name}"));
        }
        self.fns.push(name);
        walk(self);
        self.fns.pop();
    }

    /// Whether the `use` path being walked names the runtime module.
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

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if let syn::Type::Path(aliased) = &*item.ty
            && let Some(last) = aliased.path.segments.last()
            && READER_TYPES.iter().any(|t| last.ident == t)
        {
            self.alias(format!("type {} = {}", item.ident, last.ident));
        }
        visit::visit_item_type(self, item);
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

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.method(&call.method.to_string(), call.args.len());
        visit::visit_expr_method_call(self, call);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.literal(&lit.value());
        visit::visit_lit_str(self, lit);
    }

    fn visit_use_path(&mut self, path: &'ast syn::UsePath) {
        self.use_prefix.push(path.ident.to_string());
        visit::visit_use_path(self, path);
        self.use_prefix.pop();
    }

    fn visit_use_name(&mut self, name: &'ast syn::UseName) {
        let ident = name.ident.to_string();
        if VAR_CONSTS.contains(&ident.as_str())
            || RETIRED.contains(&ident.as_str())
            || ident == HARNESS_LOCATOR
        {
            self.met(ident);
        }
        visit::visit_use_name(self, name);
    }

    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        let ident = rename.ident.to_string();
        // `runtime_embed::{self as e}` names the module itself under `e`.
        let guarded = ident == EMBED
            || READER_TYPES.contains(&ident.as_str())
            || VAR_CONSTS.contains(&ident.as_str())
            || RETIRED.contains(&ident.as_str())
            || ident == HARNESS_LOCATOR
            || (self.under_embed() && ident == "self");
        if guarded {
            self.alias(format!("use {ident} as {}", rename.rename));
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

/// Scan `source` as the file `rel`.
fn scan(rel: &str, source: &str) -> Result<Scan, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse: {e}"))?;
    let mut found = Scan {
        embed: rel == EMBED_MODULE,
        ..Scan::default()
    };
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

/// Scan every non-test source of [`TREES`], keyed by its path from the root.
///
/// An out-of-line `cfg(test)` module may sort before the file declaring it, so
/// every file is scanned first and the test modules are dropped after.
fn scan_trees() -> Result<BTreeMap<String, Scan>, String> {
    let root = repo_root();
    let mut scanned = Vec::new();
    for tree in TREES {
        let files = panic_scan::rust_sources(&root.join(tree), panic_scan::Want::RustFiles)
            .map_err(|e| format!("{tree}: {e}"))?;
        for file in files {
            let rel = file
                .strip_prefix(&root)
                .map_err(|e| format!("{}: {e}", file.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            let source =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let found = scan(&rel, &source).map_err(|e| format!("{}: {e}", file.display()))?;
            scanned.push((file, rel, found));
        }
    }
    let mut skipped: Vec<PathBuf> = Vec::new();
    for (file, _, found) in &scanned {
        let dir = child_dir(file);
        for name in &found.test_mods {
            skipped.push(dir.join(format!("{name}.rs")));
            skipped.push(dir.join(name));
        }
    }
    let mut out = BTreeMap::new();
    for (file, rel, found) in scanned {
        if skipped.iter().any(|skip| file.starts_with(skip)) {
            continue;
        }
        out.insert(rel, found);
    }
    Ok(out)
}

/// The admitted shape of `rel`: every site [`ADMITTED`] names there, met once
/// each at its count, so a planted line is judged on its own.
fn baseline(rel: &str) -> &'static str {
    match rel {
        PIPELINE => {
            "use crate::runtime_embed::{RuntimeEmit, RuntimeSource};\n\
             fn from_env() { RuntimeEmit::from_env(); }\n\
             fn build_with_options_into() { RuntimeSource::resolve(o, e, r); }\n\
             fn build_loose_file_into() { RuntimeSource::resolve(o, e, r); }\n\
             fn build_test_into() { RuntimeSource::resolve(o, None, r); }\n\
             fn build_project_into() { RuntimeSource::resolve(o, e, r); }\n\
             fn compile_source_set_here() { let r = o.runtime_origin.admitted_runtime(r); }\n"
        }
        HEALTH => "fn check_runtime() { runtime_check(RuntimeSource::resolve(o, None, r)); }\n",
        HARNESS => {
            "use ipe_env::artifact::{ProvenRuntime, in_repo_runtime_src};\n\
             fn require_runtime() { in_repo_runtime_src(&anchor); }\n"
        }
        EMBED_MODULE => {
            "pub const RUNTIME_DIR_VAR: &str = \"IPE_RUNTIME_DIR\";\n\
             pub const RUNTIME_VENDORED_VAR: &str = \"IPE_RUNTIME_VENDORED\";\n\
             fn from_env() { parse(ipe_env::var_os(RUNTIME_VENDORED_VAR)); }\n\
             fn parse() { refuse(RUNTIME_VENDORED_VAR); }\n\
             fn resolve() { resolve_from(ipe_env::var_os(RUNTIME_DIR_VAR)); }\n\
             fn ancestors(start: &Path) { start.ancestors().take(64) }\n\
             fn prove(p: &Path) { for d in CEILING.ancestors(p) {} }\n"
        }
        _ => "",
    }
}

/// The refusals of `planted` added to the admitted shape of `rel`.
fn planted(rel: &str, line: &str) -> Result<Vec<String>, String> {
    let mut found = BTreeMap::new();
    let source = format!("{}{line}", baseline(rel));
    found.insert(rel.to_owned(), scan(rel, &source)?);
    Ok(refusals(&found))
}

/// Every runtime read and locator spelling sits only at its admitted sites.
#[test]
fn runtime_reads_sit_only_at_admitted_sites() -> Result<(), String> {
    let found = scan_trees()?;
    let mut refused = refusals(&found);
    for (_, rel, _, _) in ADMITTED {
        if !found.contains_key(*rel) {
            refused.push(format!("{rel}: an admitted file is not scanned"));
        }
    }
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    Ok(())
}

/// Each banned shape, planted beside a file's admitted shape, is refused.
#[test]
fn a_planted_runtime_read_is_refused() -> Result<(), String> {
    let harness = HARNESS;
    let regen = "tools/regen-goldens/src/main.rs";
    let cli = "src/ipe-cli/src/cache.rs";
    let cases = [
        // A runtime variable read outside its one reader.
        (
            harness,
            "fn require_runtime() { ipe_env::var_os(\"IPE_RUNTIME_DIR\"); }\n",
        ),
        (
            regen,
            "fn main() { let v = std::env::var(r\"IPE_RUNTIME_VENDORED\"); }\n",
        ),
        (
            cli,
            "fn other() { m!(std::env::var(\"IPE_RUNTIME_DIR\")); }\n",
        ),
        (
            cli,
            "fn other() { ipe_env::var_os(crate::runtime_embed::RUNTIME_DIR_VAR); }\n",
        ),
        (cli, "use crate::runtime_embed::RUNTIME_VENDORED_VAR;\n"),
        (
            EMBED_MODULE,
            "fn other() { ipe_env::var_os(RUNTIME_DIR_VAR); }\n",
        ),
        (EMBED_MODULE, "const SECOND: &str = \"IPE_RUNTIME_DIR\";\n"),
        // A reader reached from a second site, or twice at an admitted one.
        (cli, "fn other() { RuntimeSource::resolve(o, None, r); }\n"),
        (
            cli,
            "fn other() { m!(crate::runtime_embed::RuntimeEmit::from_env()); }\n",
        ),
        (
            HEALTH,
            "fn check_runtime() { RuntimeSource::resolve(o, None, r); }\n",
        ),
        (
            PIPELINE,
            "fn build_test_into() { RuntimeEmit::from_env(); }\n",
        ),
        // An empty path built in a runtime resolver.
        (cli, "fn runtime_root() -> PathBuf { PathBuf::new() }\n"),
        (
            EMBED_MODULE,
            "fn fallback() -> PathBuf { PathBuf::default() }\n",
        ),
        // An unbounded ancestor walk or a current-directory read in a locator.
        (
            cli,
            "fn find_runtime(p: &Path) { for d in p.ancestors() {} }\n",
        ),
        (
            harness,
            "fn require_runtime() { let c = std::env::current_dir(); }\n",
        ),
        (regen, "fn runtime_dir() { m!(cwd.current_dir()); }\n"),
        (EMBED_MODULE, "fn prove(p: &Path) { m!(p.ancestors()); }\n"),
        // A retired resolver defined, called or imported.
        (cli, "fn materialize() {}\n"),
        (cli, "fn other() { resolve_in_repo(a); }\n"),
        (
            harness,
            "fn require_runtime() { ipe_env::artifact::resolve_runtime_src(o, c); }\n",
        ),
        (cli, "fn other() { let e = runtime_dep_from_env(); }\n"),
        (cli, "fn other() { m!(resolve_runtime()); }\n"),
        (
            cli,
            "use super::build_pipeline::resolve_vendored_runtime_dir;\n",
        ),
        // The gate admission dropped from the compile core, or taken twice.
        (
            PIPELINE,
            "fn compile_source_set_here() { m!(o.runtime_origin.admitted_runtime(r)); }\n",
        ),
        // The harness locator reached outside the harness anchor.
        (
            cli,
            "fn locate() { ipe_env::artifact::in_repo_runtime_src(&cwd); }\n",
        ),
        (cli, "use ipe_env::artifact::in_repo_runtime_src;\n"),
        (
            harness,
            "fn other() { m!(ipe_env::artifact::in_repo_runtime_src(&cwd)); }\n",
        ),
        (
            regen,
            "use ipe_env::artifact::in_repo_runtime_src as locate;\n",
        ),
        // Second names.
        (cli, "use crate::runtime_embed as embedded;\n"),
        (cli, "use crate::runtime_embed::{self as embedded};\n"),
        (cli, "use crate::runtime_embed::RuntimeSource as Source;\n"),
        (cli, "type Source = crate::runtime_embed::RuntimeEmit;\n"),
        (cli, "use crate::runtime_embed::*;\n"),
    ];
    for (rel, source) in cases {
        let refused = planted(rel, source)?;
        assert!(!refused.is_empty(), "{rel}: {source} must be refused");
    }
    Ok(())
}

/// Each admitted shape passes on its own, and test-only code is not judged.
#[test]
fn the_admitted_shape_passes() -> Result<(), String> {
    let test_code = "#[cfg(test)]\nmod tests { fn t() { resolve_runtime(); } }\n\
                     #[test]\nfn direct() { RuntimeSource::resolve(o, None, r); }\n";
    for rel in [PIPELINE, HEALTH, EMBED_MODULE, HARNESS] {
        let refused = planted(rel, test_code)?;
        assert!(refused.is_empty(), "{rel}: {}", refused.join("\n"));
    }
    let unbounded_outside_a_locator = "fn walk_up(p: &Path) { for d in p.ancestors() {} }\n";
    let refused = planted("src/ipe-cli/src/cache.rs", unbounded_outside_a_locator)?;
    assert!(refused.is_empty(), "{}", refused.join("\n"));
    Ok(())
}

//! Entropy-site inventory: every random draw in the runtime goes through
//! `entropy::fill_entropy`, the one fallible OS source.
//!
//! Clippy bans the OS draw, uuid's clock and `OsRng` for the cfgs a clippy leg
//! builds; this scan covers the rest (the wasm32 arms, the features no leg
//! enables, and test code). It counts, per file, enclosing item and counted
//! form, every site that could draw entropy past `fill_entropy`, and asserts
//! the counts equal [`ADMITTED`]. A new site, a dropped one, or one moved into
//! another item turns the scan red.
//!
//! Every `.rs` file under `src/` is parsed with `syn`, so comments and string
//! literals are never code. No `cfg` exempts a node: the ban is total, and a
//! test injects a failing fill through a seam rather than calling the OS
//! source. A file that does not parse fails the scan. A macro body is scanned
//! token by token.
//!
//! Counted forms:
//! - every path through the `getrandom` crate (a call, a fn pointer, a type,
//!   `getrandom::Error`), from its `getrandom` segment on;
//! - every `OsRng` and `rand_core` segment;
//! - `Uuid::{new,now}_v{1,4,6,7}` on a `Uuid` path or a recorded alias of one,
//!   and `Timestamp::now` likewise;
//! - a `use` or `extern crate` naming or renaming one of those crates or items,
//!   a `type` alias of one, an `impl` for one, and a qualified `<T>` self type
//!   naming one, each under its own key;
//! - an `include!` and a `#[path]` module (bare or under `cfg_attr`), which
//!   compile a file under a name this walk does not scan it as.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ForeignItem, ImplItem, Item, Macro, Meta, Path, QSelf, TraitItem, Type,
    UseTree,
};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The OS entropy crate, counted at every path through it.
const OS_CRATE: &str = "getrandom";

/// Segments counted wherever they appear: the generator crates and the OS
/// generators they and `ring` expose. No generator crate is a runtime
/// dependency (see [`RNG_CRATES`]), so a site names one only to draw past
/// `fill_entropy`.
const RNG_SEGMENTS: &[&str] = &[
    "OsRng",
    "rand_core",
    "rand",
    "rand_chacha",
    "fastrand",
    "oorandom",
    "nanorand",
    "thread_rng",
    "ThreadRng",
    "SystemRandom",
];

/// The uuid generators that draw their own entropy or read their own clock.
const UUID_MINTS: &[&str] = &[
    "new_v1", "new_v4", "new_v6", "new_v7", "now_v1", "now_v4", "now_v6", "now_v7",
];

/// The names a `use` or `extern crate` must not rename.
const WATCHED_NAMES: &[&str] = &[
    "getrandom",
    "rand_core",
    "rand",
    "rand_chacha",
    "fastrand",
    "oorandom",
    "nanorand",
    "thread_rng",
    "ThreadRng",
    "SystemRandom",
    "OsRng",
    "uuid",
    "Uuid",
    "Timestamp",
];

/// The enclosing name of a site outside every function and constant.
const MODULE_LEVEL: &str = "<module>";

/// The counted form of an `include!`, whose file may lie outside the walk.
const INCLUDE: &str = "include!";

/// Every admitted site: file, enclosing item, counted form, count.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    // The runtime's one entropy source.
    ("entropy.rs", "fill_entropy", "getrandom::getrandom", 1),
    // The ban proofs: each names its banned path under `#[expect]`, so a
    // stale path breaks the build and an unmatched ban leaves an unfulfilled
    // expectation.
    (
        "clippy_paths_resolve.rs",
        "_ENTROPY",
        "getrandom::getrandom",
        1,
    ),
    ("clippy_paths_resolve.rs", "_UUID", "Timestamp::now", 1),
    ("clippy_paths_resolve.rs", "_RAND_CORE", "OsRng", 1),
    // A view of the in-tree `config_postgres.rs`, which the walk also reads.
    ("config_postgres_test.rs", MODULE_LEVEL, "#[path] mod pg", 1),
    (
        "postgres_placeholder_rewrite_test.rs",
        MODULE_LEVEL,
        INCLUDE,
        1,
    ),
    // The driver-selected `config`: the in-tree `config_postgres.rs`.
    ("mod.rs", MODULE_LEVEL, "#[path] mod config", 1),
    // The bridge's wire grammar, a child module of the port glue; it draws
    // no entropy.
    (
        "js_port_glue.rs",
        MODULE_LEVEL,
        "#[path] mod native_bridge",
        1,
    ),
    // The shared home-reader rows, [`INCLUDED_OUTSIDE_SRC`], scanned below.
    ("system.rs", MODULE_LEVEL, INCLUDE, 1),
];

/// The files an admitted `include!` reads from outside `src/`, relative to the
/// crate root; each must hold no site.
const INCLUDED_OUTSIDE_SRC: &[&str] = &["tests/data/home_cases.rs"];

/// Whether `tokens` hold the identifier `name`, at any group depth.
fn tokens_name(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Group(group) => tokens_name(group.stream(), name),
        TokenTree::Ident(id) => id.unraw() == name,
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// Whether `attrs` give a module a `#[path]`, bare or inside a `cfg_attr`.
fn sets_a_module_path(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("path")
            || (attr.path().is_ident("cfg_attr")
                && matches!(&attr.meta, Meta::List(list) if tokens_name(list.tokens.clone(), "path")))
    })
}

/// The segment names of `path`.
fn names_of(path: &Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.unraw().to_string())
        .collect()
}

/// Every entropy site in one file, by enclosing item and counted form.
struct Scan {
    within: Vec<String>,
    sites: BTreeMap<(String, String), usize>,
    /// `Uuid` and every name recorded as an alias of it.
    uuid_names: BTreeSet<String>,
    /// `Timestamp` and every name recorded as an alias of it.
    timestamp_names: BTreeSet<String>,
}

impl Default for Scan {
    fn default() -> Self {
        Self {
            within: Vec::new(),
            sites: BTreeMap::new(),
            uuid_names: BTreeSet::from(["Uuid".to_owned()]),
            timestamp_names: BTreeSet::from(["Timestamp".to_owned()]),
        }
    }
}

impl Scan {
    fn record(&mut self, form: String) {
        let within = self
            .within
            .last()
            .cloned()
            .unwrap_or_else(|| MODULE_LEVEL.to_owned());
        let count = self.sites.entry((within, form)).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Whether `name` is a type this scan watches under any of its names.
    fn watched_type(&self, name: &str) -> bool {
        RNG_SEGMENTS.contains(&name)
            || self.uuid_names.contains(name)
            || self.timestamp_names.contains(name)
    }

    /// Records `alias` as a second name of `target` when `target` is a
    /// watched type.
    fn alias(&mut self, target: &str, alias: String) {
        if self.uuid_names.contains(target) {
            self.uuid_names.insert(alias);
        } else if self.timestamp_names.contains(target) {
            self.timestamp_names.insert(alias);
        }
    }

    /// The watched type `ty` names, through any parentheses or invisible
    /// group.
    fn named_type(&self, ty: &Type) -> Option<String> {
        match ty {
            Type::Paren(inner) => self.named_type(&inner.elem),
            Type::Group(inner) => self.named_type(&inner.elem),
            Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.unraw().to_string())
                .filter(|name| self.watched_type(name)),
            _ => None,
        }
    }

    /// Records the entropy forms in a path given as its segment names.
    fn segments(&mut self, names: &[String]) {
        if let Some(rest) = names
            .iter()
            .position(|name| name == OS_CRATE)
            .and_then(|at| names.get(at..))
        {
            self.record(rest.join("::"));
        }
        for (at, name) in names.iter().enumerate() {
            let next = names.get(at.saturating_add(1)).map(String::as_str);
            if RNG_SEGMENTS.contains(&name.as_str()) {
                self.record(name.clone());
            }
            if let Some(mint) = next.filter(|n| UUID_MINTS.contains(n))
                && self.uuid_names.contains(name)
            {
                self.record(format!("Uuid::{mint}"));
            }
            if next == Some("now") && self.timestamp_names.contains(name) {
                self.record("Timestamp::now".to_owned());
            }
        }
    }

    /// Records every entropy form in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let mut path: Vec<String> = Vec::new();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => {
                    self.segments(&std::mem::take(&mut path));
                    self.scan_tokens(group.stream());
                }
                TokenTree::Ident(id) => {
                    let joined = at.checked_sub(2).is_some_and(|before| {
                        matches!(
                            (trees.get(before), trees.get(before.saturating_add(1))),
                            (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                                if a.as_char() == ':' && b.as_char() == ':'
                        )
                    });
                    if !joined {
                        self.segments(&std::mem::take(&mut path));
                    }
                    if id.unraw() == "include"
                        && matches!(
                            trees.get(at.saturating_add(1)),
                            Some(TokenTree::Punct(bang)) if bang.as_char() == '!'
                        )
                    {
                        self.record(INCLUDE.to_owned());
                    }
                    path.push(id.unraw().to_string());
                }
                TokenTree::Punct(p) if p.as_char() == ':' => {}
                TokenTree::Punct(_) | TokenTree::Literal(_) => {
                    self.segments(&std::mem::take(&mut path));
                }
            }
        }
        self.segments(&path);
    }

    /// Scans an item's body under its name.
    fn scoped<F: FnOnce(&mut Self)>(&mut self, name: String, scan: F) {
        self.within.push(name);
        scan(self);
        self.within.pop();
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            Item::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_item(scan, item));
                return;
            }
            Item::Const(c) => {
                let name = c.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_item(scan, item));
                return;
            }
            Item::Static(s) => {
                let name = s.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_item(scan, item));
                return;
            }
            Item::Type(alias) => {
                if let Some(name) = self.named_type(&alias.ty) {
                    self.record(format!("type {} = {name}", alias.ident.unraw()));
                    self.alias(&name, alias.ident.unraw().to_string());
                }
            }
            Item::Impl(block) => {
                if let Some(name) = self.named_type(&block.self_ty) {
                    self.record(format!("impl for {name}"));
                }
            }
            Item::ExternCrate(krate) => {
                let name = krate.ident.unraw().to_string();
                if WATCHED_NAMES.contains(&name.as_str()) {
                    match &krate.rename {
                        Some((_, rename)) => {
                            self.record(format!("extern crate {name} as {}", rename.unraw()));
                        }
                        None => self.record(format!("extern crate {name}")),
                    }
                }
            }
            Item::Mod(module) if sets_a_module_path(&module.attrs) => {
                self.record(format!("#[path] mod {}", module.ident.unraw()));
            }
            _ => {}
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        match item {
            ImplItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            ImplItem::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_impl_item(scan, item));
                return;
            }
            ImplItem::Const(c) => {
                let name = c.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_impl_item(scan, item));
                return;
            }
            ImplItem::Type(alias) => {
                if let Some(name) = self.named_type(&alias.ty) {
                    self.record(format!("type {} = {name}", alias.ident.unraw()));
                }
            }
            _ => {}
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        match item {
            TraitItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            TraitItem::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.scoped(name, |scan| visit::visit_trait_item(scan, item));
                return;
            }
            _ => {}
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if let ForeignItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_foreign_item(self, item);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Verbatim(tokens) = expr {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_expr(self, expr);
    }

    /// An attribute's argument tokens are code to an attribute macro (an
    /// `instrument(fields(..))` expression), so they are scanned like a
    /// macro body.
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if let Meta::List(list) = &attr.meta {
            self.scan_tokens(list.tokens.clone());
        }
        visit::visit_attribute(self, attr);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        self.segments(&names_of(path));
        visit::visit_path(self, path);
    }

    fn visit_qself(&mut self, qself: &'ast QSelf) {
        if let Type::Path(path) = &*qself.ty {
            let names = names_of(&path.path);
            if names
                .iter()
                .any(|name| name == OS_CRATE || self.watched_type(name))
            {
                self.record(format!("<{}>", names.join("::")));
            }
        }
        visit::visit_qself(self, qself);
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        match tree {
            UseTree::Path(p) => {
                let name = p.ident.unraw().to_string();
                if name == OS_CRATE || RNG_SEGMENTS.contains(&name.as_str()) {
                    self.record(format!("use {name}"));
                }
            }
            UseTree::Name(n) => {
                let name = n.ident.unraw().to_string();
                if name == OS_CRATE || RNG_SEGMENTS.contains(&name.as_str()) {
                    self.record(format!("use {name}"));
                }
            }
            UseTree::Rename(r) => {
                let name = r.ident.unraw().to_string();
                if WATCHED_NAMES.contains(&name.as_str()) {
                    let rename = r.rename.unraw().to_string();
                    self.record(format!("use {name} as {rename}"));
                    self.alias(&name, rename);
                }
            }
            UseTree::Glob(_) | UseTree::Group(_) => {}
        }
        visit::visit_use_tree(self, tree);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident.unraw() == "include")
        {
            self.record(INCLUDE.to_owned());
        }
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every entropy site in `src`, by enclosing item and counted form; a source
/// that does not parse fails.
fn entropy_sites(name: &str, src: &str) -> BTreeMap<(String, String), usize> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its entropy sites cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.sites
}

/// `sites` as a counted map, for fixture assertions.
fn counted(sites: &[(&str, &str, usize)]) -> BTreeMap<(String, String), usize> {
    sites
        .iter()
        .map(|(within, form, n)| (((*within).to_owned(), (*form).to_owned()), *n))
        .collect()
}

/// A site keyed by file, enclosing item and counted form.
type SiteKey = (String, String, String);

/// Every entropy site in `sources`, keyed by file.
fn tree_sites(sources: &[(String, String)]) -> BTreeMap<SiteKey, usize> {
    let mut found = BTreeMap::new();
    for (name, src) in sources {
        for ((within, form), count) in entropy_sites(name, src) {
            found.insert((name.clone(), within, form), count);
        }
    }
    found
}

/// [`ADMITTED`] as a counted map.
fn admitted() -> BTreeMap<SiteKey, usize> {
    ADMITTED
        .iter()
        .map(|(file, within, form, count)| {
            (
                ((*file).to_owned(), (*within).to_owned(), (*form).to_owned()),
                *count,
            )
        })
        .collect()
}

/// The runtime's `src/` tree, checked to hold the files the inventory names.
fn runtime_sources() -> Vec<(String, String)> {
    let sources = rust_sources(&e2e_support::manifest_dir!().join("src"));
    for required in ["entropy.rs", "clippy_paths_resolve.rs", "uuid_kernel.rs"] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    sources
}

/// `sources` with `entropy.rs` replaced by `edit` applied to it.
fn with_entropy_rs(
    sources: &[(String, String)],
    edit: impl Fn(&str) -> String,
) -> Vec<(String, String)> {
    sources
        .iter()
        .map(|(name, src)| {
            if name == "entropy.rs" {
                (name.clone(), edit(src))
            } else {
                (name.clone(), src.clone())
            }
        })
        .collect()
}

/// The admitted draw, as `entropy.rs` spells it.
const ADMITTED_DRAW: &str = "getrandom::getrandom(buf).map_err(|_| EntropyError)";

/// The keys on which `a` and `b` disagree.
fn differing(a: &BTreeMap<SiteKey, usize>, b: &BTreeMap<SiteKey, usize>) -> BTreeSet<SiteKey> {
    a.keys()
        .chain(b.keys())
        .filter(|key| a.get(*key) != b.get(*key))
        .cloned()
        .collect()
}

#[allow(clippy::expect_used)] // an unreadable fixture must fail the test, never be skipped
fn read_crate_file(rel: &str) -> String {
    std::fs::read_to_string(e2e_support::manifest_dir!().join(rel)).expect("read a crate file")
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// Every entropy site in the runtime, test code included, is an admitted site
/// at its admitted count.
#[test]
fn inventory_is_exact() {
    assert_eq!(
        tree_sites(&runtime_sources()),
        admitted(),
        "a random draw must go through `entropy::fill_entropy`; any other site must be \
         admitted in ADMITTED with its reason"
    );
    for rel in INCLUDED_OUTSIDE_SRC {
        assert_eq!(
            entropy_sites(rel, &read_crate_file(rel)),
            BTreeMap::new(),
            "{rel} is compiled into `src/` through `include!`"
        );
    }
}

/// The scan sees the admitted draw, and a tree without it reports the stale
/// row.
#[test]
fn positive_control() {
    let sources = runtime_sources();
    let found = tree_sites(&sources);
    let row = (
        "entropy.rs".to_owned(),
        "fill_entropy".to_owned(),
        "getrandom::getrandom".to_owned(),
    );
    assert_eq!(found.get(&row), Some(&1));
    let edited = with_entropy_rs(&sources, |src| {
        assert_eq!(src.matches(ADMITTED_DRAW).count(), 1);
        src.replace(ADMITTED_DRAW, "Ok(())")
    });
    let without = tree_sites(&edited);
    assert_eq!(without.get(&row), None);
    assert_eq!(
        differing(&without, &admitted()),
        BTreeSet::from([row]),
        "a dropped admitted draw must be reported as the one stale row"
    );
}

/// Moving the admitted draw into another function is one stale row and one
/// new row, never an unchanged count.
#[test]
fn swap_is_two_rows() {
    let edited = with_entropy_rs(&runtime_sources(), |src| {
        format!(
            "{}\nfn elsewhere(buf: &mut [u8]) {{ let _ = getrandom::getrandom(buf); }}\n",
            src.replace(ADMITTED_DRAW, "Ok(())")
        )
    });
    assert_eq!(
        differing(&tree_sites(&edited), &admitted()),
        BTreeSet::from([
            (
                "entropy.rs".to_owned(),
                "elsewhere".to_owned(),
                "getrandom::getrandom".to_owned(),
            ),
            (
                "entropy.rs".to_owned(),
                "fill_entropy".to_owned(),
                "getrandom::getrandom".to_owned(),
            ),
        ])
    );
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must count or must not be blinded by.
// ---------------------------------------------------------------------------

/// Each evasion fixture yields its non-admitted row.
#[test]
fn evasion_shapes_are_seen() {
    let shapes: &[(&str, &str, &str)] = &[
        ("use_item_rename.rs", MODULE_LEVEL, "use getrandom as g"),
        ("use_crate_rename.rs", MODULE_LEVEL, "use getrandom as gr"),
        (
            "extern_crate_rename.rs",
            MODULE_LEVEL,
            "extern crate getrandom as x",
        ),
        ("fn_pointer.rs", "draw", "getrandom::getrandom"),
        ("qself.rs", "draw", "<getrandom::Error>"),
        ("type_alias.rs", MODULE_LEVEL, "type R = OsRng"),
        ("impl_for.rs", MODULE_LEVEL, "impl for OsRng"),
        ("uuid_new_v4.rs", "mint", "Uuid::new_v4"),
        ("uuid_now_v7.rs", MODULE_LEVEL, "use Uuid as Id"),
        ("timestamp_now.rs", "stamp", "Timestamp::now"),
        ("macro_body.rs", MODULE_LEVEL, "getrandom::getrandom"),
        ("include.rs", "draw", INCLUDE),
        ("path_mod.rs", MODULE_LEVEL, "#[path] mod y"),
        ("cfg_attr_path.rs", MODULE_LEVEL, "#[path] mod y"),
        ("test_only.rs", "t", "getrandom::getrandom"),
        ("attribute_tokens.rs", "handle", "Uuid::new_v4"),
        ("rand_crate.rs", "roll", "rand"),
        ("ring_random.rs", "draw", "SystemRandom"),
    ];
    for (fixture, within, form) in shapes {
        let rel = format!("tests/fixtures/entropy_scan/{fixture}");
        let sites = entropy_sites(fixture, &read_crate_file(&rel));
        assert_eq!(
            sites.get(&((*within).to_owned(), (*form).to_owned())),
            Some(&1),
            "{fixture}: the scan must count `{form}` in `{within}`; it found {sites:?}"
        );
    }
}

/// A direct generator call and one through a recorded alias are both counted.
#[test]
fn a_uuid_mint_through_an_alias_is_counted() {
    let src = read_crate_file("tests/fixtures/entropy_scan/uuid_now_v7.rs");
    assert_eq!(
        entropy_sites("uuid_now_v7.rs", &src),
        counted(&[
            (MODULE_LEVEL, "use Uuid as Id", 1),
            ("mint", "Uuid::now_v7", 2),
        ])
    );
}

#[test]
fn strings_comments_and_other_types_new_v4_are_not_counted() {
    let src = r#"
/// `getrandom::getrandom` is prose.
fn open() {
    // OsRng.fill_bytes(&mut b)
    let s = "uuid::Uuid::new_v4()";
    let socket = tokio::net::TcpSocket::new_v4();
    let id = uuid::Uuid::parse_str(s);
    let built = uuid::Builder::from_random_bytes(bytes).into_uuid();
    let at = Instant::now();
}
"#;
    assert_eq!(entropy_sites("fixture", src), BTreeMap::new());
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = entropy_sites("fixture", "fn open( { getrandom::getrandom(b) }");
}

// ---------------------------------------------------------------------------
// The manifests carry no generator: no uuid RNG feature, no generator crate,
// no rename of a watched crate.
// ---------------------------------------------------------------------------

/// The uuid features that compile a generator drawing its own entropy or
/// reading its own clock.
const UUID_RNG_FEATURES: &[&str] = &[
    "v1",
    "v4",
    "v6",
    "v7",
    "rng",
    "rng-getrandom",
    "rng-rand",
    "fast-rng",
    "js",
];

/// The generator crates no manifest may depend on: each draws past
/// `fill_entropy`, and `rand`'s `thread_rng` panics when its seed draw fails.
const RNG_CRATES: &[&str] = &[
    "rand",
    "rand_core",
    "rand_chacha",
    "rand_pcg",
    "rand_xorshift",
    "fastrand",
    "oorandom",
    "nanorand",
];

/// The crates a dependency key must name as themselves: a `package = ..`
/// rename hides them from the clippy bans and from this scan.
const UNRENAMED_CRATES: &[&str] = &["getrandom", "uuid"];

/// The dependency table kinds of a manifest.
const DEPENDENCY_KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

/// The dependency tables of a manifest, the target-specific ones included.
fn dependency_tables(manifest: &toml::Table) -> Vec<(String, &toml::Table)> {
    let mut tables = Vec::new();
    for kind in DEPENDENCY_KINDS {
        if let Some(table) = manifest.get(kind).and_then(toml::Value::as_table) {
            tables.push((kind.to_owned(), table));
        }
    }
    let targets = manifest.get("target").and_then(toml::Value::as_table);
    for (cfg, target) in targets.into_iter().flatten() {
        for kind in DEPENDENCY_KINDS {
            if let Some(table) = target.get(kind).and_then(toml::Value::as_table) {
                tables.push((format!("target.{cfg}.{kind}"), table));
            }
        }
    }
    tables
}

/// Every generator `manifest` admits: a uuid RNG feature (in a dependency or
/// through a `uuid/<f>` feature reference), a generator crate, or a renamed
/// watched crate.
fn manifest_generators(manifest: &toml::Table) -> Vec<String> {
    let mut found = Vec::new();
    for (section, table) in dependency_tables(manifest) {
        for (key, spec) in table {
            let package = spec
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(key);
            if package != key
                && (UNRENAMED_CRATES.contains(&package) || RNG_CRATES.contains(&package))
            {
                found.push(format!("{section}: `{key}` renames `{package}`"));
            }
            if RNG_CRATES.contains(&package) {
                found.push(format!("{section}: generator crate `{package}`"));
            }
            if package == "uuid" {
                let features = spec.get("features").and_then(toml::Value::as_array);
                for feature in features
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
                {
                    if UUID_RNG_FEATURES.contains(&feature) {
                        found.push(format!("{section}: uuid feature `{feature}`"));
                    }
                }
            }
        }
    }
    let features = manifest.get("features").and_then(toml::Value::as_table);
    for (name, implied) in features.into_iter().flatten() {
        for entry in implied
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            let feature = entry
                .strip_prefix("uuid/")
                .or_else(|| entry.strip_prefix("uuid?/"));
            if feature.is_some_and(|f| UUID_RNG_FEATURES.contains(&f)) {
                found.push(format!("feature `{name}` implies `{entry}`"));
            }
        }
    }
    found
}

/// `text` parsed as TOML; text that does not parse fails the check.
fn parse_toml(name: &str, text: &str) -> toml::Table {
    let parsed = text.parse::<toml::Table>();
    assert!(
        parsed.is_ok(),
        "{name} does not parse as TOML: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    parsed.unwrap_or_default()
}

/// The wasm manifest `project.rs` emits, cut from its `WASM_CARGO_TOML`
/// literal.
fn emitted_wasm_manifest() -> String {
    const OPEN: &str = "const WASM_CARGO_TOML: &str = r#\"";
    let src = read_crate_file("../../compiler/backend/rust/src/project.rs");
    let text = src
        .split_once(OPEN)
        .and_then(|(_, rest)| rest.split_once("\"#;"))
        .map(|(text, _)| text.to_owned());
    assert!(
        text.is_some(),
        "project.rs: the WASM_CARGO_TOML literal was not found"
    );
    text.unwrap_or_default()
}

#[test]
fn manifests_carry_no_generator() {
    let sources = [
        ("Cargo.toml", read_crate_file("Cargo.toml")),
        (
            "templates/Cargo.toml",
            read_crate_file("../../compiler/backend/rust/templates/Cargo.toml"),
        ),
        ("project.rs WASM_CARGO_TOML", emitted_wasm_manifest()),
    ];
    for (name, text) in &sources {
        let parsed = parse_toml(name, text);
        assert!(
            dependency_tables(&parsed)
                .iter()
                .any(|(_, table)| table.contains_key("uuid")),
            "{name}: the uuid dependency was not found, so its features were not read"
        );
        assert_eq!(
            manifest_generators(&parsed),
            Vec::<String>::new(),
            "{name}: ids draw through `entropy::fill_entropy`; no manifest may admit \
             another generator"
        );
    }
}

/// Each manifest shape that admits a generator is refused, a multi-line
/// feature array, a table-form dependency and a target table included.
#[test]
fn manifest_generators_are_refused() {
    let shapes: &[(&str, usize)] = &[
        (
            "[dependencies]\nuuid = { version = \"1\", features = [\"v4\", \"v7\"] }\n",
            2,
        ),
        (
            "[dependencies]\nuuid = { version = \"1\", features = [\n  \"std\",\n  \"v4\",\n] }\n",
            1,
        ),
        (
            "[dependencies.uuid]\nversion = \"1\"\nfeatures = [\"fast-rng\"]\n",
            1,
        ),
        (
            "[target.'cfg(unix)'.dev-dependencies]\nuuid = { version = \"1\", features = [\"js\"] }\n",
            1,
        ),
        (
            "[features]\nserver = [\"uuid/v4\"]\nweb = [\"uuid?/v7\"]\n",
            2,
        ),
        ("[dependencies]\nrand = \"0.8\"\n", 1),
        ("[dev-dependencies]\nfastrand = \"2\"\n", 1),
        (
            "[dependencies]\nos = { package = \"getrandom\", version = \"0.2\" }\n",
            1,
        ),
        (
            "[dependencies]\nid = { package = \"uuid\", version = \"1\", features = [\"v4\"] }\n",
            2,
        ),
        (
            "[dependencies]\nr = { package = \"rand\", version = \"0.8\" }\n",
            2,
        ),
    ];
    for (text, refusals) in shapes {
        assert_eq!(
            manifest_generators(&parse_toml("fixture", text)).len(),
            *refusals,
            "{text}"
        );
    }
    let clean = "[dependencies]\nuuid = { version = \"1\" }\ngetrandom = \"0.2\"\n";
    assert_eq!(
        manifest_generators(&parse_toml("fixture", clean)),
        Vec::<String>::new()
    );
}

/// The entropy crates among a locked package's dependencies.
fn locked_entropy_deps(package: &toml::Value) -> Vec<String> {
    let deps = package.get("dependencies").and_then(toml::Value::as_array);
    deps.into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter(|dep| {
            let name = dep.split(' ').next().unwrap_or_default();
            name == OS_CRATE || RNG_CRATES.contains(&name)
        })
        .map(str::to_owned)
        .collect()
}

/// The workspace lockfile resolves uuid with no entropy source of its own: no
/// crate in the graph turns a uuid generator feature on.
#[test]
fn locked_uuid_has_no_entropy_source() {
    let lock = parse_toml("Cargo.lock", &read_crate_file("../../../Cargo.lock"));
    let packages = lock.get("package").and_then(toml::Value::as_array);
    let uuids: Vec<&toml::Value> = packages
        .into_iter()
        .flatten()
        .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some("uuid"))
        .collect();
    assert!(!uuids.is_empty(), "Cargo.lock: no uuid package was found");
    for uuid in uuids {
        assert_eq!(
            locked_entropy_deps(uuid),
            Vec::<String>::new(),
            "Cargo.lock: uuid must draw no entropy of its own"
        );
    }
    let fixture = parse_toml(
        "fixture",
        "[[package]]\nname = \"uuid\"\ndependencies = [\"getrandom 0.3.4\", \"js-sys\"]\n",
    );
    let refused = fixture
        .get("package")
        .and_then(toml::Value::as_array)
        .and_then(|packages| packages.first())
        .map(locked_entropy_deps);
    assert_eq!(refused.map(|deps| deps.len()), Some(1));
}

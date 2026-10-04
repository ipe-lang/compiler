#![forbid(unsafe_code)]
//! Refuses every `CargoCrate::Emitted` built outside its listed sites.
//!
//! A native binary built from an emitted crate is a binary `ipe release run`
//! reads a capability floor from, so every such build goes through
//! `FlooredBuild::run`, which embeds the floor its posture decides before cargo
//! starts. The wasm bundlers build crates no native reader runs, so they are
//! the only other sites. A `CargoCrate::Emitted` constructed anywhere else is a
//! native build that could skip the floor, and is refused.
//!
//! The scan walks the `ipe` crate's module tree from each crate root, parsing
//! every reached file with `syn`. An item, impl item, trait item or `mod`
//! declaration under an exact `#[cfg(test)]` is skipped with everything inside
//! it; any other `cfg` is scanned, so an unrecognised shape can only turn the
//! scan red. A site is any expression path or struct path whose last segment
//! is `Emitted`, whatever its prefix (`CargoCrate::`, `Self::`, an alias, a
//! glob import), and any `Emitted` token inside a macro body. A `use` naming
//! `Emitted` and a `#[path]` module are refused outright, as is `include!`,
//! which would pull in source the walk never sees. Each site is keyed by its
//! file and its enclosing item path and held to [`ADMITTED`] exactly.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ImplItem, Item, ItemImpl, ItemMod, Macro, TraitItem, Type, UseTree};

/// The variant whose construction is held.
const VARIANT: &str = "Emitted";

/// The macro that splices a file the walk does not reach.
const INCLUDE_MACRO: &str = "include";

/// Every admitted site: the file relative to `src/`, the enclosing item path,
/// and how often it constructs the variant.
const ADMITTED: &[(&str, &str, usize)] = &[
    ("driver/commands.rs", "FlooredBuild::run", 1),
    ("driver/commands.rs", "bundle_wasm", 1),
    ("driver/commands.rs", "bundle_wasi", 1),
];

/// Module nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 32;

/// One site: file relative to `src/`, enclosing item path.
type Site = (String, String);

/// What one parsed file contributes: its sites, its refusals, and the module
/// files it declares, each with the directory its own children resolve in.
#[derive(Default)]
struct FileScan {
    sites: Vec<String>,
    refusals: Vec<String>,
    children: Vec<(PathBuf, PathBuf)>,
}

/// Whether `attrs` hold an exact `#[cfg(test)]`.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| list.tokens.to_string() == "test")
    })
}

/// Whether `attr` is a `#[path]`, or a `#[cfg_attr]` that may expand to one.
fn names_a_path(attr: &Attribute) -> bool {
    attr.path().is_ident("path")
        || (attr.path().is_ident("cfg_attr")
            && attr.meta.require_list().is_ok_and(|list| {
                list.tokens
                    .clone()
                    .into_iter()
                    .any(|tree| matches!(tree, TokenTree::Ident(ident) if ident == "path"))
            }))
}

/// The last identifier of `ty`'s path, or a placeholder for any other type.
fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(|| "<type>".to_owned(), |seg| seg.ident.to_string()),
        _ => "<type>".to_owned(),
    }
}

/// The syntax visitor for one file.
struct Scanner<'a> {
    /// The directory `mod x;` declarations at the current nesting resolve in.
    dir: PathBuf,
    /// The enclosing item path.
    context: Vec<String>,
    /// The file's display name, for refusals.
    file: &'a str,
    out: FileScan,
}

impl Scanner<'_> {
    fn site(&mut self) {
        self.out.sites.push(self.context.join("::"));
    }

    fn refuse(&mut self, what: &str) {
        self.out.refusals.push(format!(
            "{}: {what} in `{}`",
            self.file,
            self.context.join("::")
        ));
    }

    /// Count every `Emitted` token in `tokens`, nested groups included.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) if ident == VARIANT => self.site(),
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.context.push(name);
        walk(self);
        self.context.pop();
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        let attrs = match item {
            Item::Const(i) => &i.attrs,
            Item::Enum(i) => &i.attrs,
            Item::ExternCrate(i) => &i.attrs,
            Item::Fn(i) => &i.attrs,
            Item::ForeignMod(i) => &i.attrs,
            Item::Impl(i) => &i.attrs,
            Item::Macro(i) => &i.attrs,
            Item::Mod(i) => &i.attrs,
            Item::Static(i) => &i.attrs,
            Item::Struct(i) => &i.attrs,
            Item::Trait(i) => &i.attrs,
            Item::TraitAlias(i) => &i.attrs,
            Item::Type(i) => &i.attrs,
            Item::Union(i) => &i.attrs,
            Item::Use(i) => &i.attrs,
            Item::Verbatim(tokens) => {
                self.scan_tokens(tokens.clone());
                return;
            }
            _ => {
                self.refuse("an item shape this scan does not know");
                return;
            }
        };
        if is_test_only(attrs) {
            return;
        }
        match item {
            Item::Fn(f) => {
                let name = f.sig.ident.to_string();
                self.within(name, |s| visit::visit_item_fn(s, f));
            }
            Item::Const(c) => {
                let name = c.ident.to_string();
                self.within(name, |s| visit::visit_item_const(s, c));
            }
            Item::Static(c) => {
                let name = c.ident.to_string();
                self.within(name, |s| visit::visit_item_static(s, c));
            }
            Item::Trait(t) => {
                let name = t.ident.to_string();
                self.within(name, |s| visit::visit_item_trait(s, t));
            }
            _ => visit::visit_item(self, item),
        }
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let name = item.trait_.as_ref().map_or_else(
            || type_name(&item.self_ty),
            |(_, path, _)| {
                format!(
                    "<{} as {}>",
                    type_name(&item.self_ty),
                    path.segments
                        .last()
                        .map_or_else(String::new, |seg| seg.ident.to_string())
                )
            },
        );
        self.within(name, |s| visit::visit_item_impl(s, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        match item {
            ImplItem::Fn(f) if !is_test_only(&f.attrs) => {
                let name = f.sig.ident.to_string();
                self.within(name, |s| visit::visit_impl_item_fn(s, f));
            }
            ImplItem::Const(c) if !is_test_only(&c.attrs) => visit::visit_impl_item_const(self, c),
            ImplItem::Type(t) if !is_test_only(&t.attrs) => visit::visit_impl_item_type(self, t),
            ImplItem::Macro(m) if !is_test_only(&m.attrs) => visit::visit_impl_item_macro(self, m),
            ImplItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            ImplItem::Fn(_) | ImplItem::Const(_) | ImplItem::Type(_) | ImplItem::Macro(_) => {}
            _ => self.refuse("an impl item shape this scan does not know"),
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        match item {
            TraitItem::Fn(f) if !is_test_only(&f.attrs) => {
                let name = f.sig.ident.to_string();
                self.within(name, |s| visit::visit_trait_item_fn(s, f));
            }
            TraitItem::Const(c) if !is_test_only(&c.attrs) => {
                visit::visit_trait_item_const(self, c);
            }
            TraitItem::Type(t) if !is_test_only(&t.attrs) => visit::visit_trait_item_type(self, t),
            TraitItem::Macro(m) if !is_test_only(&m.attrs) => {
                visit::visit_trait_item_macro(self, m);
            }
            TraitItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            TraitItem::Fn(_) | TraitItem::Const(_) | TraitItem::Type(_) | TraitItem::Macro(_) => {}
            _ => self.refuse("a trait item shape this scan does not know"),
        }
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.attrs.iter().any(names_a_path) {
            self.refuse("a `#[path]` module");
            return;
        }
        let name = item.ident.to_string();
        let child_dir = self.dir.join(&name);
        if item.content.is_some() {
            let outer = std::mem::replace(&mut self.dir, child_dir);
            self.within(name, |s| visit::visit_item_mod(s, item));
            self.dir = outer;
            return;
        }
        let flat = self.dir.join(format!("{name}.rs"));
        let nested = child_dir.join("mod.rs");
        match (flat.is_file(), nested.is_file()) {
            (true, false) => self.out.children.push((flat, child_dir)),
            (false, true) => self.out.children.push((nested, child_dir)),
            (true, true) | (false, false) => {
                self.refuse(&format!("module `{name}` without exactly one file"));
            }
        }
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        match tree {
            UseTree::Name(name) if name.ident == VARIANT => self.refuse("a `use` of `Emitted`"),
            UseTree::Rename(rename) if rename.ident == VARIANT => {
                self.refuse("a renaming `use` of `Emitted`");
            }
            _ => visit::visit_use_tree(self, tree),
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        let path = match expr {
            Expr::Path(path) => Some(&path.path),
            Expr::Struct(strukt) => Some(&strukt.path),
            _ => None,
        };
        if path
            .and_then(|path| path.segments.last())
            .is_some_and(|seg| seg.ident == VARIANT)
        {
            self.site();
        }
        visit::visit_expr(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac.path.is_ident(INCLUDE_MACRO) {
            self.refuse("an `include!`");
        }
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Scan one parsed file named `file`, whose `mod x;` declarations resolve in `dir`.
fn scan_file(file: &str, dir: PathBuf, syntax: &syn::File) -> FileScan {
    let mut scanner = Scanner {
        dir,
        context: Vec::new(),
        file,
        out: FileScan::default(),
    };
    if is_test_only(&syntax.attrs) {
        return scanner.out;
    }
    scanner.visit_file(syntax);
    scanner.out
}

/// The `ipe` crate's `src/` directory.
fn src_root() -> PathBuf {
    e2e_support::manifest_dir!().join("src")
}

/// Every crate root under `root`, each with the directory its modules resolve in.
fn crate_roots(root: &Path) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let mut roots = vec![
        (root.join("lib.rs"), root.to_path_buf()),
        (root.join("main.rs"), root.to_path_buf()),
    ];
    let bin = root.join("bin");
    for entry in std::fs::read_dir(&bin)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            roots.push((path, bin.clone()));
        }
    }
    Ok(roots)
}

/// What the module-tree walk found.
struct Walked {
    /// Every site, with how often it occurs.
    sites: BTreeMap<Site, usize>,
    /// Every refused construct.
    refusals: Vec<String>,
    /// Every file reached, relative to `src/`.
    reached: BTreeSet<String>,
}

/// The sites and refusals of every file reached from `roots`, keyed relative to `root`.
fn walk(root: &Path, roots: Vec<(PathBuf, PathBuf)>) -> Result<Walked, Box<dyn std::error::Error>> {
    let mut sites: BTreeMap<Site, usize> = BTreeMap::new();
    let mut refusals = Vec::new();
    let mut reached = BTreeSet::new();
    let mut queue: Vec<(PathBuf, PathBuf, usize)> = roots
        .into_iter()
        .map(|(file, dir)| (file, dir, 0))
        .collect();
    while let Some((file, dir, depth)) = queue.pop() {
        let rel = file
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        if !reached.insert(rel.clone()) {
            continue;
        }
        if depth > MAX_DEPTH {
            refusals.push(format!("{rel}: module tree deeper than {MAX_DEPTH}"));
            continue;
        }
        let syntax = syn::parse_file(&std::fs::read_to_string(&file)?)?;
        let scan = scan_file(&rel, dir, &syntax);
        for context in scan.sites {
            let seen = sites.entry((rel.clone(), context)).or_default();
            *seen = seen.saturating_add(1);
        }
        refusals.extend(scan.refusals);
        let next = depth.saturating_add(1);
        queue.extend(
            scan.children
                .into_iter()
                .map(|(child, child_dir)| (child, child_dir, next)),
        );
    }
    Ok(Walked {
        sites,
        refusals,
        reached,
    })
}

/// Every difference between `sites` and [`ADMITTED`], one line each.
fn drift(sites: &BTreeMap<Site, usize>) -> Vec<String> {
    let expected: BTreeMap<Site, usize> = ADMITTED
        .iter()
        .map(|(file, context, count)| (((*file).to_owned(), (*context).to_owned()), *count))
        .collect();
    let keys: BTreeSet<&Site> = sites.keys().chain(expected.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let got = sites.get(key).copied().unwrap_or(0);
            let want = expected.get(key).copied().unwrap_or(0);
            (got != want).then(|| {
                format!(
                    "{}: `{VARIANT}` constructed in `{}` x{got} (admitted: {want})",
                    key.0, key.1
                )
            })
        })
        .collect()
}

/// The sites and refusals of `source` parsed as the file `rel`.
fn scan_source(rel: &str, source: &str) -> syn::Result<(BTreeMap<Site, usize>, Vec<String>)> {
    let syntax = syn::parse_file(source)?;
    let scan = scan_file(rel, PathBuf::from("/nonexistent"), &syntax);
    let mut sites = BTreeMap::new();
    for context in scan.sites {
        let seen: &mut usize = sites.entry((rel.to_owned(), context)).or_default();
        *seen = seen.saturating_add(1);
    }
    Ok((sites, scan.refusals))
}

/// The admitted sites as `driver/commands.rs` source, with `extra` appended.
fn commands_with(extra: &str) -> String {
    format!(
        "impl<'a> FlooredBuild<'a> {{ fn run(self) {{ let _ = CargoCrate::Emitted(self.crate_dir); }} }}\n\
         pub fn bundle_wasm(d: &OwnedDir) {{ let _ = CargoCrate::Emitted(d); }}\n\
         pub fn bundle_wasi(d: &OwnedDir) {{ let _ = CargoCrate::Emitted(d); }}\n\
         {extra}"
    )
}

#[test]
fn emitted_cargo_build_only_runs_through_floored_build() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let Walked {
        sites,
        refusals,
        reached,
    } = walk(&root, roots).expect("module tree walkable");
    for file in [
        "cargo_step.rs",
        "driver/commands.rs",
        "driver/commands_pkg.rs",
        "watch.rs",
    ] {
        assert!(
            reached.contains(file),
            "the walk must reach src/{file}, or it is walking the wrong tree"
        );
    }
    let mut found = refusals;
    found.extend(drift(&sites));
    assert!(
        found.is_empty(),
        "every native build of an emitted crate goes through `FlooredBuild::run`, which \
         embeds the floor its posture decides; `CargoCrate::Emitted` must match ADMITTED:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_admitted_sites_alone_pass() {
    let (sites, refusals) =
        scan_source("driver/commands.rs", &commands_with("")).expect("sample parses");
    assert!(refusals.is_empty(), "{refusals:?}");
    assert!(drift(&sites).is_empty(), "{:?}", drift(&sites));
}

#[test]
fn an_emitted_crate_built_elsewhere_is_refused() {
    let refused = [
        (
            "driver/commands.rs",
            "fn run_dev() { let _ = CargoCrate::Emitted(d); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let k = crate::cargo_step::CargoCrate::Emitted; }",
        ),
        ("driver/commands.rs", "fn f() { let _ = Emitted(d); }"),
        (
            "driver/commands.rs",
            "fn f() { let _ = vec![CargoCrate::Emitted(d)]; }",
        ),
        (
            "driver/commands.rs",
            "impl<'a> FlooredBuild<'a> { fn run(self) { let _ = CargoCrate::Emitted(d); } }",
        ),
        (
            "driver/commands.rs",
            "impl<'a> FlooredBuild<'a> { fn other(self) { let _ = CargoCrate::Emitted(d); } }",
        ),
        (
            "driver/commands.rs",
            "fn bundle_wasm2() { fn bundle_wasm() { let _ = CargoCrate::Emitted(d); } }",
        ),
        (
            "driver/commands.rs",
            "use crate::cargo_step::CargoCrate::Emitted as E;",
        ),
        (
            "driver/commands.rs",
            "use crate::cargo_step::CargoCrate::{Emitted};",
        ),
        ("driver/commands.rs", "include!(\"elsewhere.rs\");"),
        ("driver/commands.rs", "#[path = \"x.rs\"] mod x;"),
        ("driver/commands.rs", "mod absent_module;"),
        (
            "driver/commands.rs",
            "#[cfg(any(test, feature = \"x\"))] fn f() { let _ = CargoCrate::Emitted(d); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { #[cfg(test)] let _ = CargoCrate::Emitted(d); }",
        ),
    ];
    for (rel, sample) in refused {
        let (sites, refusals) = scan_source(rel, &commands_with(sample)).expect("sample parses");
        assert!(
            !refusals.is_empty() || !drift(&sites).is_empty(),
            "the scan must refuse in {rel}: {sample}"
        );
    }
    let (sites, refusals) = scan_source(
        "driver/commands_pkg.rs",
        "fn assemble_desktop() { let _ = Self::Emitted(d); }",
    )
    .expect("sample parses");
    assert!(
        !refusals.is_empty() || !drift(&sites).is_empty(),
        "the scan must refuse a site in another file"
    );
}

#[test]
fn a_test_only_construction_and_a_pattern_are_not_sites() {
    let admitted = [
        "#[cfg(test)] mod tests { fn t() { let _ = CargoCrate::Emitted(d); } }",
        "#[cfg(test)] fn helper() { let _ = CargoCrate::Emitted(d); }",
        "impl CargoCrate<'_> { fn path(&self) { match self { Self::Emitted(d) => d, _ => x } } }",
        "fn f(k: CargoCrate) { if let CargoCrate::Emitted(d) = k {} }",
        "/// See [`CargoCrate::Emitted`].\nfn documented() {}",
        "fn f() { let _ = \"CargoCrate::Emitted\"; }",
    ];
    for sample in admitted {
        let (sites, refusals) =
            scan_source("driver/commands.rs", &commands_with(sample)).expect("sample parses");
        assert!(refusals.is_empty(), "{sample}: {refusals:?}");
        assert!(drift(&sites).is_empty(), "{sample}: {:?}", drift(&sites));
    }
}

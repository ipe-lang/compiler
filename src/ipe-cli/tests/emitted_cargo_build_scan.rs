#![forbid(unsafe_code)]
//! Refuses every cargo build of an emitted crate outside its listed sites.
//!
//! A native binary built from an emitted crate is a binary `ipe release run`
//! reads a capability floor from, so the build must start from a crate whose
//! floor line is known. Two acts are held, at the act itself:
//!
//! - building the `cargo build` command — `build_command`, called only by
//!   `CargoBuild::command` and `WatchBuild::command` (every other cargo child
//!   is held by `cargo_step_scan`);
//! - constructing each value those two commands build from: a
//!   `CargoCrate::Emitted` (only in `FlooredBuild::run`, which embeds the floor
//!   its posture decides, and the wasm bundlers, whose crates no native reader
//!   runs), a `WatchBuild` (only in the watch loop's `spawn_cargo_build`, from a
//!   `DevMarkedCrate`), an `EmittedCrate` (only in `write_emitted_project`, which
//!   wrote the floor it records) and a `DevMarkedCrate` (only in
//!   `EmittedCrate::dev_marked`, which checks that floor).
//!
//! The scan walks the `ipe` crate's module tree from each crate root, parsing
//! every reached file with `syn`. An item, impl item, trait item or `mod`
//! declaration under an exact `#[cfg(test)]` is skipped with everything inside
//! it; any other `cfg` is scanned, so an unrecognised shape can only turn the
//! scan red. A site is any expression path, struct path or method name whose
//! last segment is a held name, whatever its prefix (`CargoCrate::`, `Self::`,
//! a glob import), a `Self { .. }` inside an `impl` of a held type, and any held
//! token inside a macro body. A `use` naming `Emitted` or `build_command`, a
//! renaming `use` and a type alias of any held name, a `#[path]` module and an
//! `include!` (which would pull in source the walk never sees) are refused
//! outright. Each site is keyed by its file, its enclosing item path and the
//! held name, and held to [`ADMITTED`] exactly.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Ident, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ImplItem, ImplItemType, Item, ItemImpl, ItemMod, ItemType, Macro, TraitItem,
    TraitItemType, Type, UseTree,
};

/// How a `use` of a held name is judged.
#[derive(Clone, Copy)]
enum UsePolicy {
    /// Any `use` naming it is refused: it is reached only by its own path.
    Refused,
    /// A plain `use` is admitted; a renaming one is refused.
    RenameRefused,
}

/// Every held name, with how a `use` of it is judged. A name held with
/// [`UsePolicy::RenameRefused`] is a type, so a type alias of it is refused too.
const HELD: &[(&str, UsePolicy)] = &[
    ("Emitted", UsePolicy::Refused),
    ("build_command", UsePolicy::Refused),
    ("WatchBuild", UsePolicy::RenameRefused),
    ("EmittedCrate", UsePolicy::RenameRefused),
    ("DevMarkedCrate", UsePolicy::RenameRefused),
];

/// The macro that splices a file the walk does not reach.
const INCLUDE_MACRO: &str = "include";

/// Every admitted site: the file relative to `src/`, the enclosing item path,
/// the held name, and how often it occurs there.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    ("cargo_step.rs", "CargoBuild::command", "build_command", 1),
    ("cargo_step.rs", "WatchBuild::command", "build_command", 1),
    (
        "driver/build_pipeline.rs",
        "EmittedCrate::dev_marked",
        "DevMarkedCrate",
        1,
    ),
    (
        "driver/build_pipeline.rs",
        "write_emitted_project",
        "EmittedCrate",
        1,
    ),
    ("driver/commands.rs", "FlooredBuild::run", "Emitted", 1),
    ("driver/commands.rs", "bundle_wasm", "Emitted", 1),
    ("driver/commands.rs", "bundle_wasi", "Emitted", 1),
    ("watch.rs", "spawn_cargo_build", "WatchBuild", 1),
];

/// Module nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 32;

/// One site: file relative to `src/`, enclosing item path, held name.
type Site = (String, String, String);

/// What one parsed file contributes: its sites (enclosing item path, held
/// name), its refusals, and the module files it declares, each with the
/// directory its own children resolve in.
#[derive(Default)]
struct FileScan {
    sites: Vec<(String, String)>,
    refusals: Vec<String>,
    children: Vec<(PathBuf, PathBuf)>,
}

/// The held name `spelled` is, if any.
fn held(spelled: &str) -> Option<&'static str> {
    HELD.iter()
        .map(|(name, _)| *name)
        .find(|name| *name == spelled)
}

/// The use policy of the held name `ident` spells, if any.
fn use_policy(ident: &Ident) -> Option<(&'static str, UsePolicy)> {
    HELD.iter().copied().find(|(name, _)| ident == name)
}

/// Whether `ident` spells a held type name.
fn is_held_type(ident: &Ident) -> bool {
    use_policy(ident).is_some_and(|(_, policy)| matches!(policy, UsePolicy::RenameRefused))
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
    /// The self type of each enclosing `impl`, innermost last.
    impl_self: Vec<String>,
    /// How many type aliases enclose the current node.
    in_alias: usize,
    /// The file's display name, for refusals.
    file: &'a str,
    out: FileScan,
}

impl Scanner<'_> {
    fn site(&mut self, name: &str) {
        self.out
            .sites
            .push((self.context.join("::"), name.to_owned()));
    }

    fn refuse(&mut self, what: &str) {
        self.out.refusals.push(format!(
            "{}: {what} in `{}`",
            self.file,
            self.context.join("::")
        ));
    }

    /// Count every held token in `tokens`, nested groups included.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    if let Some(name) = held(&ident.to_string()) {
                        self.site(name);
                    }
                }
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.context.push(name);
        walk(self);
        self.context.pop();
    }

    fn aliasing(&mut self, walk: impl FnOnce(&mut Self)) {
        self.in_alias = self.in_alias.saturating_add(1);
        walk(self);
        self.in_alias = self.in_alias.saturating_sub(1);
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
        let self_name = type_name(&item.self_ty);
        let name = item.trait_.as_ref().map_or_else(
            || self_name.clone(),
            |(path, _)| {
                format!(
                    "<{self_name} as {}>",
                    path.segments
                        .last()
                        .map_or_else(String::new, |seg| seg.ident.to_string())
                )
            },
        );
        self.impl_self.push(self_name);
        self.within(name, |s| visit::visit_item_impl(s, item));
        self.impl_self.pop();
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        match item {
            ImplItem::Fn(f) if !is_test_only(&f.attrs) => {
                let name = f.sig.ident.to_string();
                self.within(name, |s| visit::visit_impl_item_fn(s, f));
            }
            ImplItem::Const(c) if !is_test_only(&c.attrs) => visit::visit_impl_item_const(self, c),
            ImplItem::Type(t) if !is_test_only(&t.attrs) => self.visit_impl_item_type(t),
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
            TraitItem::Type(t) if !is_test_only(&t.attrs) => self.visit_trait_item_type(t),
            TraitItem::Macro(m) if !is_test_only(&m.attrs) => {
                visit::visit_trait_item_macro(self, m);
            }
            TraitItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            TraitItem::Fn(_) | TraitItem::Const(_) | TraitItem::Type(_) | TraitItem::Macro(_) => {}
            _ => self.refuse("a trait item shape this scan does not know"),
        }
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        self.aliasing(|s| visit::visit_item_type(s, item));
    }

    fn visit_impl_item_type(&mut self, item: &'ast ImplItemType) {
        self.aliasing(|s| visit::visit_impl_item_type(s, item));
    }

    fn visit_trait_item_type(&mut self, item: &'ast TraitItemType) {
        self.aliasing(|s| visit::visit_trait_item_type(s, item));
    }

    fn visit_ident(&mut self, ident: &'ast Ident) {
        if self.in_alias > 0 && is_held_type(ident) {
            self.refuse(&format!("a type alias of `{ident}`"));
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
            UseTree::Name(name) => {
                if let Some((held, UsePolicy::Refused)) = use_policy(&name.ident) {
                    self.refuse(&format!("a `use` of `{held}`"));
                }
            }
            UseTree::Rename(rename) => {
                if let Some((held, _)) = use_policy(&rename.ident) {
                    self.refuse(&format!("a renaming `use` of `{held}`"));
                }
            }
            UseTree::Path(_) | UseTree::Glob(_) | UseTree::Group(_) => {
                visit::visit_use_tree(self, tree);
            }
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        let last = match expr {
            Expr::Path(path) => path.path.segments.last().map(|seg| seg.ident.to_string()),
            // `Self { .. }` constructs the enclosing impl's self type.
            Expr::Struct(strukt) if strukt.path.is_ident("Self") => self.impl_self.last().cloned(),
            Expr::Struct(strukt) => strukt.path.segments.last().map(|seg| seg.ident.to_string()),
            Expr::MethodCall(call) => Some(call.method.to_string()),
            _ => None,
        };
        if let Some(name) = last.as_deref().and_then(held) {
            self.site(name);
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
        impl_self: Vec::new(),
        in_alias: 0,
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

/// Add one file's sites to `sites`, keyed by `rel`.
fn tally(sites: &mut BTreeMap<Site, usize>, rel: &str, found: Vec<(String, String)>) {
    for (context, name) in found {
        let seen = sites.entry((rel.to_owned(), context, name)).or_default();
        *seen = seen.saturating_add(1);
    }
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
        tally(&mut sites, &rel, scan.sites);
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

/// Every difference between `sites` and the [`ADMITTED`] rows `files` selects,
/// one line each.
fn drift(sites: &BTreeMap<Site, usize>, files: impl Fn(&str) -> bool) -> Vec<String> {
    let expected: BTreeMap<Site, usize> = ADMITTED
        .iter()
        .filter(|(file, ..)| files(file))
        .map(|(file, context, name, count)| {
            (
                (
                    (*file).to_owned(),
                    (*context).to_owned(),
                    (*name).to_owned(),
                ),
                *count,
            )
        })
        .collect();
    let keys: BTreeSet<&Site> = sites.keys().chain(expected.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let got = sites.get(key).copied().unwrap_or(0);
            let want = expected.get(key).copied().unwrap_or(0);
            (got != want).then(|| {
                format!(
                    "{}: `{}` in `{}` x{got} (admitted: {want})",
                    key.0, key.2, key.1
                )
            })
        })
        .collect()
}

/// The sites and refusals of `source` parsed as the file `rel`, and the drift
/// from the [`ADMITTED`] rows of `rel` alone.
fn scan_source(rel: &str, source: &str) -> syn::Result<(Vec<String>, Vec<String>)> {
    let syntax = syn::parse_file(source)?;
    let scan = scan_file(rel, PathBuf::from("/nonexistent"), &syntax);
    let mut sites = BTreeMap::new();
    tally(&mut sites, rel, scan.sites);
    Ok((drift(&sites, |file| file == rel), scan.refusals))
}

/// The admitted sites of `rel` as source, with `extra` appended.
fn admitted_with(rel: &str, extra: &str) -> String {
    let admitted = match rel {
        "driver/commands.rs" => {
            "impl<'a> FlooredBuild<'a> { fn run(self) { let _ = CargoCrate::Emitted(self.crate_dir); } }\n\
             pub fn bundle_wasm(d: &OwnedDir) { let _ = CargoCrate::Emitted(d); }\n\
             pub fn bundle_wasi(d: &OwnedDir) { let _ = CargoCrate::Emitted(d); }\n"
        }
        "cargo_step.rs" => {
            "impl CargoBuild<'_> { fn command(&self) -> Command { build_command(self.cargo.path(), d) } }\n\
             impl WatchBuild<'_> { fn command(&self) -> Command { build_command(self.cargo, d) } }\n\
             fn build_command(cargo: &Path, dir: &Path) -> Command { Command::new(cargo) }\n"
        }
        "watch.rs" => {
            "fn spawn_cargo_build(krate: crate::DevMarkedCrate<'_>) {\n\
             let build = crate::cargo_step::WatchBuild { cargo, krate, target_dir, accel, verbosity };\n\
             }\n"
        }
        "driver/build_pipeline.rs" => {
            "pub fn write_emitted_project() -> Result<EmittedCrate, CliError> {\n\
             Ok(EmittedCrate { dir: crate_dir, floor })\n\
             }\n\
             impl EmittedCrate {\n\
             pub fn dev_marked(&self) -> Result<DevMarkedCrate<'_>, CliError> {\n\
             Ok(DevMarkedCrate { path: self.dir.path() })\n\
             }\n\
             #[cfg(test)] pub(crate) const fn assume_written(dir: OwnedDir, floor: EmitFloor) -> Self { Self { dir, floor } }\n\
             }\n"
        }
        _ => "",
    };
    format!("{admitted}{extra}")
}

/// Every file holding an admitted site.
const ADMITTED_FILES: &[&str] = &[
    "cargo_step.rs",
    "driver/build_pipeline.rs",
    "driver/commands.rs",
    "watch.rs",
];

#[test]
fn emitted_cargo_build_only_runs_through_its_admitted_sites() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let Walked {
        sites,
        refusals,
        reached,
    } = walk(&root, roots).expect("module tree walkable");
    for file in ADMITTED_FILES.iter().chain(&["driver/commands_pkg.rs"]) {
        assert!(
            reached.contains(*file),
            "the walk must reach src/{file}, or it is walking the wrong tree"
        );
    }
    let mut found = refusals;
    found.extend(drift(&sites, |_| true));
    assert!(
        found.is_empty(),
        "every cargo build of an emitted crate starts from a crate whose floor line is \
         known; each held name must match ADMITTED:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_admitted_sites_alone_pass() {
    for rel in ADMITTED_FILES {
        let (drift, refusals) = scan_source(rel, &admitted_with(rel, "")).expect("sample parses");
        assert!(refusals.is_empty(), "{rel}: {refusals:?}");
        assert!(drift.is_empty(), "{rel}: {drift:?}");
    }
}

fn assert_every_sample_is_refused(refused: &[(&str, &str)]) {
    for (rel, sample) in refused {
        let (drift, refusals) =
            scan_source(rel, &admitted_with(rel, sample)).expect("sample parses");
        assert!(
            !refusals.is_empty() || !drift.is_empty(),
            "the scan must refuse in {rel}: {sample}"
        );
    }
}

#[test]
fn a_held_act_elsewhere_is_refused() {
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
        (
            "driver/commands_pkg.rs",
            "fn assemble_desktop() { let _ = Self::Emitted(d); }",
        ),
    ];
    assert_every_sample_is_refused(&refused);
}

#[test]
fn a_watch_build_constructed_elsewhere_is_refused() {
    let refused = [
        // The watch build, constructed outside the watch loop.
        (
            "watch.rs",
            "fn f() { let _ = WatchBuild { cargo, crate_dir, .. }; }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = WatchBuild { cargo, crate_dir, .. }; }",
        ),
        (
            "cargo_step.rs",
            "impl WatchBuild<'_> { fn again(&self) -> Self { Self { ..*self } } }",
        ),
        (
            "watch.rs",
            "fn f() { let _ = vec![crate::cargo_step::WatchBuild { cargo }]; }",
        ),
        ("watch.rs", "use crate::cargo_step::WatchBuild as W;"),
        (
            "watch.rs",
            "type W<'a> = crate::cargo_step::WatchBuild<'a>;",
        ),
    ];
    assert_every_sample_is_refused(&refused);
}

#[test]
fn the_cargo_build_command_built_elsewhere_is_refused() {
    let refused = [
        // The cargo build command, built outside the two admitted commands.
        (
            "cargo_step.rs",
            "fn f() { let _ = build_command(cargo, dir, p, t, o); }",
        ),
        (
            "cargo_step.rs",
            "impl WatchBuild<'_> { fn spawn(&self) { let _ = build_command(self.cargo, d); } }",
        ),
        (
            "cargo_step.rs",
            "impl CargoBuild<'_> { fn command(&self) { let _ = build_command(a, b); } }",
        ),
        ("cargo_step.rs", "fn f() { let g = build_command; }"),
        ("cargo_step.rs", "fn f() { let _ = x.build_command(); }"),
        ("cargo_step.rs", "fn f() { dbg!(build_command(a, b)); }"),
        ("watch.rs", "use crate::cargo_step::build_command;"),
    ];
    assert_every_sample_is_refused(&refused);
}

#[test]
fn a_floor_witness_constructed_elsewhere_is_refused() {
    let refused = [
        // The floor witnesses, constructed outside the code that proves them.
        (
            "driver/commands.rs",
            "fn f() { let _ = EmittedCrate { dir, floor }; }",
        ),
        (
            "driver/build_pipeline.rs",
            "impl EmittedCrate { fn forge(dir: OwnedDir) -> Self { Self { dir, floor: EmitFloor::DevelopmentMarker } } }",
        ),
        (
            "driver/build_pipeline.rs",
            "fn f() { let _ = DevMarkedCrate { path }; }",
        ),
        ("driver/build_pipeline.rs", "type Witness = EmittedCrate;"),
        (
            "driver/commands.rs",
            "use crate::driver::DevMarkedCrate as Dev;",
        ),
        (
            "driver/build_pipeline.rs",
            "impl Tr for X { type W<'a> = DevMarkedCrate<'a>; }",
        ),
    ];
    assert_every_sample_is_refused(&refused);
}

#[test]
fn a_test_only_construction_a_pattern_and_a_type_position_are_not_sites() {
    let admitted = [
        (
            "driver/commands.rs",
            "#[cfg(test)] mod tests { fn t() { let _ = CargoCrate::Emitted(d); } }",
        ),
        (
            "driver/commands.rs",
            "#[cfg(test)] fn helper() { let _ = CargoCrate::Emitted(d); }",
        ),
        (
            "driver/commands.rs",
            "impl CargoCrate<'_> { fn path(&self) { match self { Self::Emitted(d) => d, _ => x } } }",
        ),
        (
            "driver/commands.rs",
            "fn f(k: CargoCrate) { if let CargoCrate::Emitted(d) = k {} }",
        ),
        (
            "driver/commands.rs",
            "/// See [`CargoCrate::Emitted`].\nfn documented() {}",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = \"CargoCrate::Emitted\"; }",
        ),
        (
            "driver/commands.rs",
            "fn f(c: &EmittedCrate) -> Result<EmittedCrate, CliError> { let _ = c.dir(); x }",
        ),
        (
            "driver/commands.rs",
            "use super::{EmittedCrate, OutTarget};",
        ),
        (
            "cargo_step.rs",
            "#[cfg(test)] mod tests { fn t() { let _ = super::build_command(a, b); let _ = WatchBuild { cargo }; } }",
        ),
        (
            "watch.rs",
            "fn g(k: crate::DevMarkedCrate<'_>) { let _ = k.path(); }",
        ),
    ];
    for (rel, sample) in admitted {
        let (drift, refusals) =
            scan_source(rel, &admitted_with(rel, sample)).expect("sample parses");
        assert!(refusals.is_empty(), "{rel}: {sample}: {refusals:?}");
        assert!(drift.is_empty(), "{rel}: {sample}: {drift:?}");
    }
}

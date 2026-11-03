#![forbid(unsafe_code)]
//! Refuses a cargo profile or a profile directory chosen outside the build's
//! posture.
//!
//! A build's cargo profile and the directory cargo writes its artifacts into
//! are total functions of the command's posture (`cargo_step::BuildPosture`):
//! `BuildPosture::profile` names the profile, `CargoProfile::dir_name` names
//! its directory, and every build site reads an artifact either from cargo's
//! own record or from `BuildPosture::artifact_dir`. Two acts are held:
//!
//! - naming `CargoProfile` at all outside `cargo_step.rs` (a path, a type, a
//!   `use`, a renaming `use`, a macro token): refused outright;
//! - spelling a profile directory: a string literal with a `debug` path
//!   component anywhere, and a string literal with a `release` path component
//!   anywhere inside the argument of `.join(..)`, `.push(..)`, `Path::new(..)`,
//!   `PathBuf::from(..)`, `OsStr::new(..)` or `OsString::from(..)` — a bare
//!   literal, a borrowed or parenthesised one, a `format!` template, a branch
//!   (`release` alone also names a command and an output level, so only its
//!   path-building use is held). Each site is keyed by its file, its enclosing
//!   item path and the directory, and held to [`ADMITTED`] exactly.
//!
//! The scan walks the `ipe` crate's module tree from each crate root, parsing
//! every reached file with `syn`. An item, impl item, trait item or `mod`
//! declaration under an exact `#[cfg(test)]` is skipped with everything inside
//! it; any other `cfg` is scanned, so an unrecognised shape can only turn the
//! scan red. A `#[path]` module and an `include!` (which would pull in source
//! the walk never sees) are refused outright.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Ident, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, ImplItem, Item, ItemImpl, ItemMod, LitStr, Macro, TraitItem, Type};

/// The type no module but `cargo_step.rs` may name.
const PROFILE_TYPE: &str = "CargoProfile";

/// The one module that owns the profile.
const OWNER: &str = "cargo_step.rs";

/// The development profile's directory: held in every string literal.
const DEBUG_DIR: &str = "debug";

/// The release profile's directory: held where a literal builds a path.
const RELEASE_DIR: &str = "release";

/// The methods that extend a path by their argument.
const PATH_METHODS: &[&str] = &["join", "push"];

/// The `(type, constructor)` calls that make a path from their argument.
const PATH_CONSTRUCTORS: &[(&str, &str)] = &[
    ("Path", "new"),
    ("PathBuf", "from"),
    ("OsStr", "new"),
    ("OsString", "from"),
];

/// The macro that splices a file the walk does not reach.
const INCLUDE_MACRO: &str = "include";

/// Every admitted site: the file relative to `src/`, the enclosing item path,
/// the profile directory, and how often it occurs there.
const ADMITTED: &[(&str, &str, &str, usize)] =
    &[("cargo_step.rs", "CargoProfile::dir_name", DEBUG_DIR, 1)];

/// Module nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 32;

/// One site: file relative to `src/`, enclosing item path, profile directory.
type Site = (String, String, String);

/// What one parsed file contributes: its sites (enclosing item path, profile
/// directory), its refusals, and the module files it declares, each with the
/// directory its own children resolve in.
#[derive(Default)]
struct FileScan {
    sites: Vec<(String, String)>,
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

/// Whether `text`, split at `/` and `\`, has the path component `dir`.
fn has_component(text: &str, dir: &str) -> bool {
    text.split(['/', '\\']).any(|part| part == dir)
}

/// Whether any string literal in `tokens`, nested groups included, has the
/// path component `dir`.
fn tokens_have_component(tokens: TokenStream, dir: &str) -> bool {
    tokens.into_iter().any(|tree| match &tree {
        TokenTree::Group(group) => tokens_have_component(group.stream(), dir),
        TokenTree::Literal(_) => token_str(&tree).is_some_and(|text| has_component(&text, dir)),
        TokenTree::Ident(_) | TokenTree::Punct(_) => false,
    })
}

/// Whether any string literal anywhere in an expression, macro arguments
/// included, has the path component `dir`.
struct HoldsComponent<'d> {
    dir: &'d str,
    found: bool,
}

impl<'ast> Visit<'ast> for HoldsComponent<'_> {
    fn visit_lit_str(&mut self, lit: &'ast LitStr) {
        self.found |= has_component(&lit.value(), self.dir);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.found |= tokens_have_component(mac.tokens.clone(), self.dir);
    }
}

/// Whether `expr` holds a string literal with the path component `dir`.
fn expr_has_component(expr: &Expr, dir: &str) -> bool {
    let mut holds = HoldsComponent { dir, found: false };
    holds.visit_expr(expr);
    holds.found
}

/// The string value of the literal token `tree`, if it is a string literal.
fn token_str(tree: &TokenTree) -> Option<String> {
    match tree {
        TokenTree::Literal(lit) => syn::parse_str::<LitStr>(&lit.to_string())
            .ok()
            .map(|s| s.value()),
        _ => None,
    }
}

/// The syntax visitor for one file.
struct Scanner<'a> {
    /// The directory `mod x;` declarations at the current nesting resolve in.
    dir: PathBuf,
    /// The enclosing item path.
    context: Vec<String>,
    /// The file's name relative to `src/`.
    file: &'a str,
    out: FileScan,
}

impl Scanner<'_> {
    fn site(&mut self, dir: &str) {
        self.out
            .sites
            .push((self.context.join("::"), dir.to_owned()));
    }

    fn refuse(&mut self, what: &str) {
        self.out.refusals.push(format!(
            "{}: {what} in `{}`",
            self.file,
            self.context.join("::")
        ));
    }

    fn profile_type(&mut self, ident: &Ident) {
        if self.file != OWNER && ident == PROFILE_TYPE {
            self.refuse(&format!("`{PROFILE_TYPE}` named outside `{OWNER}`"));
        }
    }

    /// A `release` path component inside the argument of a path-building call.
    fn path_arg(&mut self, held: bool) {
        if held {
            self.site(RELEASE_DIR);
        }
    }

    /// Every held token in `tokens`, nested groups included: a `CargoProfile`
    /// identifier, a `debug` string literal, and a `release` string literal
    /// anywhere in the parenthesised argument of a `join` or `push`.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut path_method = false;
        for tree in tokens {
            let after_path_method = std::mem::take(&mut path_method);
            match &tree {
                TokenTree::Ident(ident) => {
                    self.profile_type(ident);
                    path_method = PATH_METHODS.iter().any(|m| ident == m);
                }
                TokenTree::Group(group) => {
                    if after_path_method && group.delimiter() == Delimiter::Parenthesis {
                        self.path_arg(tokens_have_component(group.stream(), RELEASE_DIR));
                    }
                    self.scan_tokens(group.stream());
                }
                TokenTree::Literal(_) => {
                    if token_str(&tree).is_some_and(|text| has_component(&text, DEBUG_DIR)) {
                        self.site(DEBUG_DIR);
                    }
                }
                TokenTree::Punct(_) => {}
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
    /// A doc comment is prose about a path, never a path a build reads.
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if !attr.path().is_ident("doc") {
            visit::visit_attribute(self, attr);
        }
    }

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

    fn visit_ident(&mut self, ident: &'ast Ident) {
        self.profile_type(ident);
    }

    fn visit_lit_str(&mut self, lit: &'ast LitStr) {
        if has_component(&lit.value(), DEBUG_DIR) {
            self.site(DEBUG_DIR);
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

    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::MethodCall(call) if PATH_METHODS.iter().any(|m| call.method == m) => {
                self.path_arg(
                    call.args
                        .iter()
                        .any(|arg| expr_has_component(arg, RELEASE_DIR)),
                );
            }
            Expr::Call(call) => {
                if let Expr::Path(func) = &*call.func {
                    let segments: Vec<String> = func
                        .path
                        .segments
                        .iter()
                        .map(|seg| seg.ident.to_string())
                        .collect();
                    let constructs_a_path = PATH_CONSTRUCTORS.iter().any(|(ty, ctor)| {
                        segments.len() >= 2
                            && segments.get(segments.len() - 2).is_some_and(|s| s == ty)
                            && segments.last().is_some_and(|s| s == ctor)
                    });
                    if constructs_a_path {
                        self.path_arg(
                            call.args
                                .iter()
                                .any(|arg| expr_has_component(arg, RELEASE_DIR)),
                        );
                    }
                }
            }
            _ => {}
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

/// Add one file's sites to `sites`, keyed by `rel`.
fn tally(sites: &mut BTreeMap<Site, usize>, rel: &str, found: Vec<(String, String)>) {
    for (context, dir) in found {
        let seen = sites.entry((rel.to_owned(), context, dir)).or_default();
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
        .map(|(file, context, dir, count)| {
            (
                ((*file).to_owned(), (*context).to_owned(), (*dir).to_owned()),
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

/// The drift from the [`ADMITTED`] rows of `rel` alone and the refusals of
/// `source` parsed as the file `rel`.
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
        "cargo_step.rs" => {
            "enum CargoProfile { Dev, Release }\n\
             impl CargoProfile { const fn dir_name(self) -> &'static str { match self { Self::Dev => \"debug\", Self::Release => \"release\" } } }\n"
        }
        _ => "",
    };
    format!("{admitted}{extra}")
}

/// Every file holding an admitted site.
const ADMITTED_FILES: &[&str] = &["cargo_step.rs"];

#[test]
fn a_cargo_profile_is_chosen_only_by_the_builds_posture() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let Walked {
        sites,
        refusals,
        reached,
    } = walk(&root, roots).expect("module tree walkable");
    for file in
        ADMITTED_FILES
            .iter()
            .chain(&["driver/commands.rs", "driver/commands_pkg.rs", "watch.rs"])
    {
        assert!(
            reached.contains(*file),
            "the walk must reach src/{file}, or it is walking the wrong tree"
        );
    }
    let mut found = refusals;
    found.extend(drift(&sites, |_| true));
    assert!(
        found.is_empty(),
        "a build's cargo profile and artifact directory follow its `BuildPosture`; \
         each profile directory must match ADMITTED:\n{}",
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

#[test]
fn a_profile_chosen_at_a_build_site_is_refused() {
    let refused = [
        // The literal a browser bundle once read its artifact from.
        (
            "driver/commands.rs",
            "pub fn bundle_wasm() { let _ = target_dir.path().join(\"wasm32-unknown-unknown\").join(\"release\").join(\"ipe_app.wasm\"); }",
        ),
        (
            "driver/commands.rs",
            "fn run_run_with_args() { bin.push(\"debug\"); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = Path::new(\"target/release\"); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = std::path::PathBuf::from(\"wasm32-wasip1/release/app.wasm\"); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = dir.join(\"wasm32-wasip1\\\\release\"); }",
        ),
        ("driver/commands.rs", "const PROFILE_DIR: &str = \"debug\";"),
        (
            "driver/commands.rs",
            "fn f() { let _ = vec![dir.join(\"release\")]; }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = format!(\"{}\", dir.join(\"debug\").display()); }",
        ),
        // The profile type, named outside its owner.
        (
            "driver/commands.rs",
            "fn f() { let _ = CargoBuild { profile: CargoProfile::Release }; }",
        ),
        ("driver/commands.rs", "use crate::cargo_step::CargoProfile;"),
        (
            "driver/commands.rs",
            "use crate::cargo_step::CargoProfile as P;",
        ),
        (
            "driver/commands_pkg.rs",
            "type Profile = crate::cargo_step::CargoProfile;",
        ),
        ("driver/commands.rs", "fn f() { dbg!(CargoProfile::Dev); }"),
        // The guesses each build site once spelled.
        (
            "watch.rs",
            "fn dir_has_dep_rlib(target_dir: &Path) -> bool { let deps = target_dir.join(\"debug\").join(\"deps\"); true }",
        ),
        (
            "driver/commands_pkg.rs",
            "impl BundleProfile { const fn target_subdir(self) -> &'static str { match self { Self::Dev => \"debug\", Self::Release => \"release\" } } }",
        ),
        (
            "driver/commands_pkg.rs",
            "pub fn build_and_run_test_entry() { let compiled = target.dir().path().join(\"debug\").join(&name); }",
        ),
        // A `release` directory one expression away from the call.
        (
            "driver/commands.rs",
            "fn f() { let _ = dir.join(format!(\"{triple}/release\")); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = dir.join(&\"release\"); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = dir.join(if r { \"release\" } else { name }); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = std::ffi::OsStr::new(\"release\"); }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = vec![dir.join(format!(\"{t}/release\"))]; }",
        ),
        ("cargo_step.rs", "fn f() { let _ = dir.join(\"release\"); }"),
        // Source the walk would not see, and a scoped test gate it would.
        ("driver/commands.rs", "include!(\"elsewhere.rs\");"),
        ("driver/commands.rs", "#[path = \"x.rs\"] mod x;"),
        ("driver/commands.rs", "mod absent_module;"),
        (
            "driver/commands.rs",
            "#[cfg(any(test, feature = \"x\"))] fn f() { bin.push(\"debug\"); }",
        ),
    ];
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
fn a_test_only_site_and_another_meaning_of_release_are_not_sites() {
    let admitted = [
        (
            "driver/commands.rs",
            "#[cfg(test)] mod tests { fn t() { let _ = dir.join(\"debug\"); let _ = CargoProfile::Dev; } }",
        ),
        (
            "driver/commands.rs",
            "impl NativeFinish<'_> { const fn posture(&self) -> &'static str { match self { Self::Dev => \"development\", Self::Release { .. } => \"release\" } } }",
        ),
        (
            "output_dir.rs",
            "impl Level { const fn dir_name(self) -> &'static str { match self { Self::Release => \"release\" } } }",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = BuildPosture::Release.artifact_dir(t, target).join(name); }",
        ),
        (
            "driver/commands.rs",
            "/// Read from `target/debug/app`.\n#[doc = \"target/release\"]\nfn documented() {}",
        ),
        (
            "driver/commands.rs",
            "fn f() { let _ = dir.join(\"debugger\").join(\"releases\"); }",
        ),
    ];
    for (rel, sample) in admitted {
        let (drift, refusals) =
            scan_source(rel, &admitted_with(rel, sample)).expect("sample parses");
        assert!(refusals.is_empty(), "{rel}: {sample}: {refusals:?}");
        assert!(drift.is_empty(), "{rel}: {sample}: {drift:?}");
    }
}

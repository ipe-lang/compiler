#![forbid(unsafe_code)]
//! Pins that every emit is configured from one settings value.
//!
//! The backend is built only through `RustBackend::configured`, from an
//! `EmitSettings` the build derived once, so no producer re-lists a subset of
//! the settings by hand. The webview host is reached only from a resolved
//! delivery: `EmitHost::WebView` is built only from a manifest with a webview
//! proof, the proof is minted only by `Delivery::host_intent`, and each served
//! request is a named site. This scan parses the non-test code of the database,
//! the CLI and the wasm driver and refuses each of those spellings outside the
//! (file, function) sites admitted below, macro bodies included. Patterns are
//! never counted: matching on a host builds nothing.
//!
//! The settings a manifest owns (the browser mount base, the `[wasm]` public-env
//! allowlist and mode) are derived into `EmitSettings` at one site,
//! `manifest_emit_settings`: the driver reads each of those member chains
//! nowhere else but the admitted sites below.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// The source trees the scan judges, relative to the repository root.
const TREES: &[&str] = &["src/compiler/db/src", "src/ipe-cli/src", "src/wasm/src"];

/// The guarded `Owner::member` paths.
const GUARDED: &[(&str, &str)] = &[
    ("RustBackend", "new"),
    ("RustBackend", "configured"),
    ("EmitHost", "WebView"),
    ("HostIntent", "Served"),
    ("Delivery", "web_desktop"),
];

/// The backend's per-field setters. A setter applied to a configured backend
/// would override one setting behind the settings value, so none is called
/// from the scanned trees, as a method or by path.
const SETTERS: &[&str] = &[
    "with_project_name",
    "with_runtime_dep",
    "with_debugger",
    "with_build_intent",
    "with_hot_appearance",
    "with_target",
    "with_db_driver",
    "with_ffi",
    "with_wasm_public_env",
    "with_mount_base",
    "with_wasm_hydrate_mode",
];

/// The manifest member chains the driver reads only at admitted sites, as the
/// field names from the manifest value down.
const MEMBER_CHAINS: &[&[&str]] = &[
    &["delivery", "browser", "base"],
    &["wasm", "public_env"],
    &["wasm", "mode"],
];

/// The tree the member chains are guarded in.
const CHAIN_TREE: &str = "src/ipe-cli/src/driver/";

/// The label of a member chain, as it appears in a site and in [`ADMITTED`].
fn chain_label(chain: &[&str]) -> String {
    format!("field {}", chain.join("."))
}

/// Whether `what` is the label of a guarded member chain.
fn is_chain_label(what: &str) -> bool {
    MEMBER_CHAINS.iter().any(|chain| chain_label(chain) == what)
}

/// The webview proof: any construction of it counts.
const PROOF: &str = "WebViewProof";

/// Names that may not be renamed, aliased or have their members imported, since
/// a second name would hide a site from the scan.
const OWNERS: &[&str] = &["RustBackend", "EmitHost", "HostIntent", "Delivery", PROOF];

/// Each admitted site: what is spelled, the file, the function, and how often.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    (
        "RustBackend::configured",
        "src/compiler/db/src/lib.rs",
        "emit_project",
        1,
    ),
    (
        "RustBackend::configured",
        "src/compiler/db/src/lib.rs",
        "emit_spine_file",
        1,
    ),
    (
        "RustBackend::configured",
        "src/compiler/db/src/lib.rs",
        "emit_rust_file",
        1,
    ),
    (
        "RustBackend::configured",
        "src/compiler/db/src/lib.rs",
        "emit_manifest",
        1,
    ),
    (
        "RustBackend::configured",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "compile_source_set_observed",
        1,
    ),
    (
        "EmitHost::WebView",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "manifest_emit_settings",
        1,
    ),
    (
        "field delivery.browser.base",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "manifest_emit_settings",
        1,
    ),
    (
        "field wasm.public_env",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "manifest_emit_settings",
        1,
    ),
    (
        "field wasm.mode",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "manifest_emit_settings",
        1,
    ),
    // The mobile shell is laid out for the manifest's mount base, and a base
    // that changes during the build is refused: reads of the base, not
    // derivations of emit settings.
    (
        "field delivery.browser.base",
        "src/ipe-cli/src/driver/commands_pkg.rs",
        "assemble_mobile",
        1,
    ),
    (
        "field delivery.browser.base",
        "src/ipe-cli/src/driver/commands_pkg.rs",
        "build_under_fixed_base",
        1,
    ),
    (PROOF, "src/ipe-cli/src/delivery.rs", "host_intent", 1),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/delivery.rs",
        "host_intent",
        1,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "build_project_with_options",
        1,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/driver/build_pipeline.rs",
        "build_from_sources",
        1,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/project_root/fixture.rs",
        "build_fixture_with_options",
        1,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/driver/commands.rs",
        "run_eject",
        1,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/driver/commands.rs",
        "release_pipeline",
        2,
    ),
    (
        "HostIntent::Served",
        "src/ipe-cli/src/watch.rs",
        "watch_emit_settings",
        1,
    ),
    (
        "Delivery::web_desktop",
        "src/ipe-cli/src/driver/commands_pkg.rs",
        "gate_desktop",
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

/// The last segment of a type path, if `ty` is one.
fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// The field name of a member access.
fn member_name(member: &syn::Member) -> String {
    match member {
        syn::Member::Named(ident) => ident.to_string(),
        syn::Member::Unnamed(index) => index.index.to_string(),
    }
}

/// The field names of the access chain ending at `expr`, outermost last, seen
/// through parentheses, borrows and groups.
fn field_chain(expr: &syn::ExprField) -> Vec<String> {
    let mut names = vec![member_name(&expr.member)];
    let mut base = &*expr.base;
    loop {
        match base {
            syn::Expr::Field(field) => {
                names.push(member_name(&field.member));
                base = &field.base;
            }
            syn::Expr::Paren(inner) => base = &inner.expr,
            syn::Expr::Reference(inner) => base = &inner.expr,
            syn::Expr::Group(inner) => base = &inner.expr,
            _ => break,
        }
    }
    names.reverse();
    names
}

/// What the scan found in one source.
#[derive(Default)]
struct Scan {
    /// The enclosing function names, innermost last.
    fns: Vec<String>,
    /// The enclosing impl self types, innermost last.
    impls: Vec<Option<String>>,
    /// How deep inside a pattern the visitor is.
    in_pattern: usize,
    /// Each guarded spelling met, with the function it sits in, counted.
    sites: BTreeMap<(String, String), usize>,
    /// Each second name for a guarded owner, with the function it sits in.
    aliases: BTreeSet<(String, String)>,
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

    /// Count one guarded spelling `what`.
    fn hit(&mut self, what: String) {
        let site = self.site();
        *self.sites.entry((site, what)).or_insert(0) += 1;
    }

    /// Count the path `owner::member` when it is guarded, `Self` naming the
    /// enclosing impl's type.
    fn pair(&mut self, owner: &str, member: &str) {
        let owner = if owner == "Self" {
            let Some(Some(name)) = self.impls.last() else {
                return;
            };
            name.clone()
        } else {
            owner.to_owned()
        };
        if GUARDED.iter().any(|(o, m)| *o == owner && *m == member)
            || (owner == "RustBackend" && SETTERS.contains(&member))
        {
            self.hit(format!("{owner}::{member}"));
        }
    }

    /// Count the guarded spellings of an expression path's segments.
    fn segments(&mut self, names: &[String]) {
        if let [.., owner, member] = names {
            self.pair(owner, member);
        } else if let [only] = names
            && only == "Self"
            && matches!(self.impls.last(), Some(Some(name)) if name == PROOF)
        {
            self.hit(PROOF.to_owned());
        }
        if names.last().is_some_and(|last| last == PROOF) {
            self.hit(PROOF.to_owned());
        }
    }

    /// Count each guarded member chain the field names `names` end in.
    fn member_chains(&mut self, names: &[String]) {
        for chain in MEMBER_CHAINS {
            let wanted: Vec<String> = chain.iter().map(|field| (*field).to_owned()).collect();
            if names.ends_with(&wanted) {
                self.hit(chain_label(chain));
            }
        }
    }

    /// Count each guarded member chain a macro body spells, `name` being its
    /// last field and `previous` the tokens before it.
    fn macro_member_chains(&mut self, previous: &[String], name: &str) {
        for chain in MEMBER_CHAINS {
            let Some((last, leading)) = chain.split_last() else {
                continue;
            };
            let mut spelled: Vec<String> = Vec::new();
            for field in leading {
                spelled.push(".".to_owned());
                spelled.push((*field).to_owned());
            }
            spelled.push(".".to_owned());
            if name == *last && previous.ends_with(&spelled) {
                self.hit(chain_label(chain));
            }
        }
    }

    /// Count every guarded spelling of a macro body.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut previous: Vec<String> = Vec::new();
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if let [.., owner, colon_a, colon_b] = previous.as_slice()
                        && colon_a == ":"
                        && colon_b == ":"
                    {
                        self.pair(owner, &name);
                    }
                    if name == PROOF {
                        self.hit(PROOF.to_owned());
                    }
                    if previous.last().is_some_and(|dot| dot == ".")
                        && SETTERS.contains(&name.as_str())
                    {
                        self.hit(format!(".{name}"));
                    }
                    self.macro_member_chains(&previous, &name);
                    previous.push(name);
                }
                TokenTree::Group(group) => {
                    self.tokens(group.stream());
                    previous.clear();
                }
                TokenTree::Punct(punct) => previous.push(punct.as_char().to_string()),
                TokenTree::Literal(_) => previous.clear(),
            }
        }
    }

    /// Run `walk` inside the function `name`.
    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.fns.push(name);
        walk(self);
        self.fns.pop();
    }

    /// Record a second name for a guarded owner.
    fn alias(&mut self, what: String) {
        let site = self.site();
        self.aliases.insert((site, what));
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

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        self.impls.push(type_name(&item.self_ty));
        visit::visit_item_impl(self, item);
        self.impls.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_only(&item.attrs) {
            return;
        }
        self.within(item.sig.ident.to_string(), |scan| {
            visit::visit_impl_item_fn(scan, item);
        });
    }

    fn visit_pat(&mut self, pat: &'ast syn::Pat) {
        self.in_pattern += 1;
        visit::visit_pat(self, pat);
        self.in_pattern -= 1;
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if self.in_pattern == 0 {
            // `<Owner>::member` and `<Owner as Trait>::member` name `Owner`
            // through the qualified self type, ahead of the path's own
            // segments.
            let (owner, skip) = expr.qself.as_ref().map_or((None, 0), |qself| {
                (
                    Some(type_name(&qself.ty).unwrap_or_default()),
                    qself.position,
                )
            });
            let names: Vec<String> = owner
                .into_iter()
                .chain(
                    expr.path
                        .segments
                        .iter()
                        .skip(skip)
                        .map(|segment| segment.ident.to_string()),
                )
                .collect();
            self.segments(&names);
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let name = expr.method.to_string();
        if SETTERS.contains(&name.as_str()) {
            self.hit(format!(".{name}"));
        }
        visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_field(&mut self, expr: &'ast syn::ExprField) {
        if self.in_pattern == 0 {
            self.member_chains(&field_chain(expr));
        }
        visit::visit_expr_field(self, expr);
    }

    fn visit_expr_struct(&mut self, expr: &'ast syn::ExprStruct) {
        if expr
            .path
            .segments
            .last()
            .is_some_and(|last| last.ident == PROOF)
        {
            self.hit(PROOF.to_owned());
        }
        visit::visit_expr_struct(self, expr);
    }

    fn visit_use_path(&mut self, path: &'ast syn::UsePath) {
        if OWNERS.iter().any(|owner| path.ident == owner) {
            self.alias(format!("use {}::…", path.ident));
        }
        visit::visit_use_path(self, path);
    }

    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        if OWNERS.iter().any(|owner| rename.ident == owner) {
            self.alias(format!("use {} as {}", rename.ident, rename.rename));
        }
        visit::visit_use_rename(self, rename);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if type_name(&item.ty).is_some_and(|name| OWNERS.contains(&name.as_str())) {
            self.alias(format!("type {}", item.ident));
        }
        visit::visit_item_type(self, item);
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
            if is_chain_label(what) && !rel.starts_with(CHAIN_TREE) {
                continue;
            }
            seen.insert((what.clone(), rel.clone(), site.clone()), *count);
        }
        for (site, what) in &scan.aliases {
            out.push(format!(
                "{rel}: `{what}` in `{site}`: a second name hides a site from this scan"
            ));
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

/// Every `.rs` file under `dir`.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut work = vec![dir.to_path_buf()];
    while let Some(dir) = work.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
            if path.is_dir() {
                work.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
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
        for file in rust_files(&root.join(tree))? {
            let source =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let found = scan(&source).map_err(|e| format!("{}: {e}", file.display()))?;
            scanned.push((file, found));
        }
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

/// The backend, the webview host, the webview proof and each served request
/// are reached only at their admitted sites.
#[test]
fn emit_settings_reach_only_admitted_sites() -> Result<(), String> {
    let found = scan_trees()?;
    let mut refused = refusals(&found);
    for (_, rel, _, _) in ADMITTED {
        if !found.contains_key(*rel) {
            refused.push(format!("{rel}: an admitted file is missing"));
        }
    }
    assert!(
        refused.is_empty(),
        "every emit is configured from one settings value, and the webview host \
         is reached only from a resolved delivery; refused:\n{}",
        refused.join("\n")
    );
    Ok(())
}

/// Each guarded spelling planted outside its admitted site is refused.
#[test]
fn a_planted_site_is_refused() -> Result<(), String> {
    let db = "src/compiler/db/src/lib.rs";
    let pipeline = "src/ipe-cli/src/driver/build_pipeline.rs";
    let delivery = "src/ipe-cli/src/delivery.rs";
    let breaches = [
        (
            db,
            "fn emit_project() { ipe_backend_rust::RustBackend::new(&i); }\n",
        ),
        (db, "fn other() { RustBackend::configured(&i, &s); }\n"),
        (
            db,
            "fn other() { let _ = vec![RustBackend::configured(&i, &s)]; }\n",
        ),
        (db, "fn other() { let f = RustBackend::new; }\n"),
        (
            pipeline,
            "fn loose() { let h = ipe_backend_rust::EmitHost::WebView(w); }\n",
        ),
        (
            delivery,
            "fn other() { HostIntent::WebView(WebViewProof(())); }\n",
        ),
        (
            delivery,
            "impl WebViewProof { fn mint() -> Self { Self(()) } }\n",
        ),
        (
            pipeline,
            "fn build_project_into() { go(HostIntent::Served); }\n",
        ),
        (
            pipeline,
            "impl HostIntent { fn served() -> Self { Self::Served } }\n",
        ),
        (
            pipeline,
            "fn build_project_with_options() { go(HostIntent::Served); go(HostIntent::Served); }\n",
        ),
        (pipeline, "use crate::delivery::HostIntent::Served;\n"),
        (pipeline, "use crate::delivery::HostIntent as H;\n"),
        (pipeline, "type H = crate::delivery::HostIntent;\n"),
        (db, "fn other() { <RustBackend>::configured(&i, &s); }\n"),
        (
            db,
            "fn other() { <ipe_backend_rust::RustBackend as Clone>::new(&i); }\n",
        ),
        (
            db,
            "fn emit_project() { RustBackend::configured(&i, &s).with_debugger(true); }\n",
        ),
        (db, "fn other() { RustBackend::with_ffi(b, None); }\n"),
        (db, "fn other() { m!(b.with_project_name(n)); }\n"),
        (
            "src/ipe-cli/src/driver/commands_pkg.rs",
            "fn other() { Delivery::web_desktop().host_intent(); }\n",
        ),
        (pipeline, "use crate::delivery::Delivery as D;\n"),
    ];
    refused_by_scan(&breaches)
}

/// Each planted read of a manifest-owned browser setting outside its single
/// derivation site is refused.
#[test]
fn a_planted_browser_delivery_read_is_refused() -> Result<(), String> {
    let pipeline = "src/ipe-cli/src/driver/build_pipeline.rs";
    let commands = "src/ipe-cli/src/driver/commands.rs";
    let breaches = [
        (
            commands,
            "fn release_pipeline() { let b = m.delivery.browser.base.clone(); }\n",
        ),
        (
            commands,
            "fn release_pipeline() { let e = manifest.wasm.public_env.to_names(); }\n",
        ),
        (
            commands,
            "fn release_pipeline() { let h = w.wasm.mode.as_deref() == Some(\"hydrate\"); }\n",
        ),
        (
            commands,
            "fn release_pipeline() { let b = (&m).delivery.browser.base; }\n",
        ),
        (
            commands,
            "fn release_pipeline() { m!(manifest.delivery.browser.base); }\n",
        ),
        (
            pipeline,
            "fn loose_emit_settings() { let e = m.wasm.public_env; }\n",
        ),
        (
            pipeline,
            "fn manifest_emit_settings() { let a = m.wasm.mode; let b = m.wasm.mode; }\n",
        ),
    ];
    refused_by_scan(&breaches)
}

/// Every planted breach draws a refusal the empty source at its file does not.
fn refused_by_scan(breaches: &[(&str, &str)]) -> Result<(), String> {
    // An empty source at `rel` already misses each admitted row there; a
    // breach counts only by a refusal that baseline does not carry.
    let mut missed = Vec::new();
    for (rel, source) in breaches {
        let baseline = planted(rel, "")?;
        if planted(rel, source)?
            .iter()
            .all(|refusal| baseline.contains(refusal))
        {
            missed.push(format!("{rel}: {source}"));
        }
    }
    assert!(
        missed.is_empty(),
        "each planted breach is refused; admitted:\n{}",
        missed.join("")
    );
    Ok(())
}

/// Each guarded spelling at its admitted site, and every pattern or test
/// item, is out of scope.
#[test]
fn an_admitted_site_is_not_refused() -> Result<(), String> {
    let pipeline = "src/ipe-cli/src/driver/build_pipeline.rs";
    let delivery = "src/ipe-cli/src/delivery.rs";
    let admitted = [
        (
            pipeline,
            "fn manifest_emit_settings() { match h { HostIntent::Served => EmitHost::Served, \
             HostIntent::WebView(_) => EmitHost::WebView(w) }; }\n\
             fn compile_source_set_observed() { RustBackend::configured(&g, &s); }\n\
             fn build_project_with_options() { go(HostIntent::Served); }\n\
             fn build_from_sources() { go(HostIntent::Served); }\n\
             fn manifest_emit_settings() { let e = m.wasm.public_env.to_names(); \
             let b = m.delivery.browser.base.clone(); let h = m.wasm.mode.is_some(); }\n",
        ),
        (
            delivery,
            "impl Delivery { const fn host_intent(self) -> HostIntent { \
             if w { HostIntent::WebView(WebViewProof(())) } else { HostIntent::Served } } }\n",
        ),
        (
            "src/ipe-cli/src/driver/commands_pkg.rs",
            "fn gate_desktop() { let HostIntent::WebView(p) = Delivery::web_desktop().host_intent() \
             else { return }; }\n\
             fn assemble_mobile() { let base = &manifest.delivery.browser.base; }\n\
             fn build_under_fixed_base() { let after = parse(p)?\n.delivery\n.browser\n.base; }\n",
        ),
    ];
    for (rel, source) in admitted {
        assert_eq!(
            planted(rel, source)?,
            Vec::<String>::new(),
            "admitted in {rel}"
        );
    }
    let out_of_scope = "fn other() { let HostIntent::WebView(p) = h else { return }; \
        if let EmitHost::WebView(w) = e {} }\n\
        #[cfg(test)]\nmod tests { fn t() { RustBackend::new(&i); EmitHost::WebView(w); } }\n";
    let chains_out_of_scope = "fn other() { let WasmConfig { mode, .. } = w; let b = &m.wasm; }\n\
        #[cfg(test)]\nmod tests { fn t() { m.delivery.browser.base; m.wasm.mode; m.wasm.public_env; } }\n";
    assert_eq!(
        planted("src/ipe-cli/src/driver/commands.rs", chains_out_of_scope)?
            .iter()
            .filter(|refusal| refusal.contains("field "))
            .count(),
        0,
        "a pattern, a whole `wasm` read and test code read no guarded chain"
    );
    assert_eq!(
        planted(
            "src/ipe-cli/src/init.rs",
            "fn other() { let b = parsed.delivery.browser.base; }\n"
        )?,
        Vec::<String>::new(),
        "the guard covers the driver tree only"
    );
    assert_eq!(
        planted("src/ipe-cli/src/other.rs", out_of_scope)?,
        Vec::<String>::new(),
        "patterns and test code build nothing"
    );
    Ok(())
}

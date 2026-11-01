//! Error-bridge scan: the `From<String>` bridge into the runtime's error types
//! only shrinks, and every `Unexpected` the runtime builds is ledgered.
//!
//! Every `.rs` file under `src/` is parsed with `syn`. Two facts are counted in
//! its production syntax:
//!
//! - **The census.** Every path segment `From<String>` or `From<&str>` (an
//!   `impl` header, a bound, a turbofish, a qualified `<E as From<…>>`), with
//!   `String` matched as the last segment of an unqualified path and `&str` at
//!   any lifetime. [`TRANSITIONAL_FROM_STRING`] holds the exact count per
//!   file: a file that drops a site must shrink its row, and a file that gains
//!   one goes red.
//! - **The unclassified sites.** Every path ending in `IpeError::unexpected`,
//!   `KernelFailure::Unexpected` or `IpeErrorKind::Unexpected`, or in
//!   `ipe_error_unexpected`, keyed by the function it is written in.
//!   [`UNCLASSIFIED_SITES`] lists each `(file, fn, needle)` with its exact count
//!   and the reason the site is `Unexpected`; an unlisted site and a stale entry
//!   both go red. `Self::` resolves to the enclosing `impl`'s self type, and
//!   stays `Self` (still matched) where no `impl` encloses it. A path inside a
//!   pattern builds nothing and is not a site. A `use` rename or `type` alias
//!   of one of the three types anywhere in the file (any scope, any order)
//!   makes the alias resolve to that type, so `Kf::Unexpected` after
//!   `use KernelFailure as Kf` is a site. A `use` that imports
//!   `Unexpected`/`unexpected` by name or glob from one of the three types is
//!   itself a site: the bare name would build `Unexpected` unseen.
//!
//! Inside a macro body the same token shapes count, and `fn name { … }` names
//! the function. Attributes (doc comments) are not code. A `#[cfg(…)]` proven
//! test-only removes exactly the node it is attached to.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, GenericArgument, ImplItem, ImplItemFn, ImplItemType,
    Item, ItemFn, ItemImpl, ItemType, ItemUse, Macro, Pat, Path, PathArguments, Stmt, TraitItem,
    TraitItemFn, Type, UseTree, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The exact `From<String>` / `From<&str>` count of each file still bridged,
/// as its path relative to `src/` and the count.
const TRANSITIONAL_FROM_STRING: &[(&str, usize)] = &[
    ("auth.rs", 9),
    ("cache.rs", 8),
    ("core.rs", 9),
    ("crypto.rs", 10),
    ("crypto_core.rs", 8),
    ("db.rs", 41),
    ("decimal.rs", 3),
    ("dsn.rs", 3),
    ("email.rs", 7),
    ("error.rs", 7),
    ("external_conn.rs", 5),
    ("file.rs", 3),
    ("http_client.rs", 18),
    ("http_stream.rs", 9),
    ("jwt.rs", 4),
    ("money.rs", 3),
    ("random.rs", 1),
    ("revocation.rs", 4),
    ("server.rs", 17),
    ("server_stream.rs", 3),
    ("system.rs", 1),
    ("task.rs", 6),
    ("tea.rs", 2),
    ("threads.rs", 2),
    ("time.rs", 23),
    ("tui/app.rs", 3),
    ("web/hub.rs", 14),
    ("web/pubsub.rs", 2),
    ("webview.rs", 2),
    ("ws_client.rs", 18),
];

/// A production site that builds an `Unexpected` error on purpose.
struct Unclassified {
    /// The source path relative to `src/`.
    file: &'static str,
    /// The function the site is written in, or `<item>` outside any function.
    function: &'static str,
    /// The matched path suffix.
    needle: &'static str,
    /// How many times `needle` occurs in `function`.
    count: usize,
    /// Why the failure has no more specific kind.
    reason: &'static str,
}

/// Every production `Unexpected` the runtime builds, with its reason.
const UNCLASSIFIED_SITES: &[Unclassified] = &[
    Unclassified {
        file: "error.rs",
        function: OUTSIDE_FN,
        needle: "IpeErrorKind::Unexpected",
        count: 1,
        reason: "the `IpeErrorKind::ALL` listing of every kind: names the variant, builds no error",
    },
    Unclassified {
        file: "error.rs",
        function: "context",
        needle: "KernelFailure::Unexpected",
        count: 1,
        reason: "`KernelFailure::context` re-prefixes an `Unexpected` and keeps its kind",
    },
    Unclassified {
        file: "error.rs",
        function: "from",
        needle: "IpeError::unexpected",
        count: 2,
        reason: "transitional: the `From<String>`/`From<&str>` bridges, deleted in E-final",
    },
    Unclassified {
        file: "error.rs",
        function: "from",
        needle: "KernelFailure::Unexpected",
        count: 1,
        reason: "transitional: the `From<String>` bridge, deleted in E-final",
    },
    Unclassified {
        file: "error.rs",
        function: "ipe_error_unexpected",
        needle: "IpeError::unexpected",
        count: 1,
        reason: "the Ipê `Error.unexpected` kernel: the program names the kind",
    },
    Unclassified {
        file: "error.rs",
        function: "io_error_kind",
        needle: "IpeErrorKind::Unexpected",
        count: 1,
        reason: "the I/O kind table's fail-closed default for an unlisted `io::ErrorKind`",
    },
    Unclassified {
        file: "error.rs",
        function: "kind",
        needle: "IpeErrorKind::Unexpected",
        count: 1,
        reason: "a database failure that is neither a conflict, an outage, a denial nor a \
                 missing file: a corrupt file, a refused statement, an unclassified engine code",
    },
    Unclassified {
        file: "error.rs",
        function: "unexpected",
        needle: "IpeErrorKind::Unexpected",
        count: 1,
        reason: "the `IpeError::unexpected` constructor itself",
    },
    Unclassified {
        file: "system.rs",
        function: "from",
        needle: "KernelFailure::Unexpected",
        count: 7,
        reason: "transitional: `From<ProcessRefusal>` maps every refusal to `Unexpected`; \
                 E3 classifies each variant and removes this entry",
    },
    Unclassified {
        file: "js_port.rs",
        function: "seal_refusal_error",
        needle: "IpeError::unexpected",
        count: 1,
        reason: "a sealed reply that fails its decode for a reason other than a ceiling: \
                 the frame came from the runtime's own encoder, so the failure is a defect",
    },
];

/// The function name recorded for a site outside any function.
const OUTSIDE_FN: &str = "<item>";

/// The `Type::Path` / `Type::Reference` shapes a bridge carries.
fn is_bridged_type(ty: &Type) -> bool {
    match ty {
        Type::Path(path) => {
            path.qself.is_none()
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "String" && segment.arguments.is_none())
        }
        Type::Reference(reference) => {
            matches!(&*reference.elem, Type::Path(path) if path.qself.is_none() && path.path.is_ident("str"))
        }
        Type::Group(group) => is_bridged_type(&group.elem),
        Type::Paren(paren) => is_bridged_type(&paren.elem),
        _ => false,
    }
}

/// How many segments of `path` are `From<String>` or `From<&str>`.
fn bridge_segments(path: &Path) -> usize {
    path.segments
        .iter()
        .filter(|segment| {
            segment.ident == "From"
                && matches!(&segment.arguments, PathArguments::AngleBracketed(args)
                    if args.args.len() == 1
                        && matches!(args.args.first(), Some(GenericArgument::Type(ty)) if is_bridged_type(ty)))
        })
        .count()
}

/// The needle `names` ends in, if any.
fn site_needle(names: &[String]) -> Option<&'static str> {
    let last = names.last()?;
    if last == "ipe_error_unexpected" {
        return Some("ipe_error_unexpected");
    }
    let owner = names.len().checked_sub(2).and_then(|at| names.get(at))?;
    match (owner.as_str(), last.as_str()) {
        ("IpeError", "unexpected") => Some("IpeError::unexpected"),
        ("KernelFailure", "Unexpected") => Some("KernelFailure::Unexpected"),
        ("IpeErrorKind", "Unexpected") => Some("IpeErrorKind::Unexpected"),
        ("Self", "unexpected") => Some("Self::unexpected"),
        ("Self", "Unexpected") => Some("Self::Unexpected"),
        _ => None,
    }
}

/// The needle an alias of the type `name` stands for, if `name` is one of the
/// three error types.
fn alias_needle(name: &str) -> Option<&'static str> {
    match name {
        "IpeError" => Some("IpeError::unexpected"),
        "KernelFailure" => Some("KernelFailure::Unexpected"),
        "IpeErrorKind" => Some("IpeErrorKind::Unexpected"),
        _ => None,
    }
}

/// The needles a `use` tree imports under a name the needles do not match:
/// `Unexpected`/`unexpected` by name or glob from one of the three types.
fn use_needles(tree: &UseTree, owner: Option<&str>, out: &mut Vec<&'static str>) {
    let owned = owner.and_then(alias_needle);
    match tree {
        UseTree::Path(path) => use_needles(&path.tree, Some(&path.ident.unraw().to_string()), out),
        UseTree::Group(group) => {
            for item in &group.items {
                use_needles(item, owner, out);
            }
        }
        UseTree::Glob(_) => out.extend(owned),
        UseTree::Name(name) => {
            let name = name.ident.unraw().to_string();
            if name == "Unexpected" || name == "unexpected" {
                out.extend(owned);
            }
        }
        UseTree::Rename(rename) => {
            let name = rename.ident.unraw().to_string();
            if name == "Unexpected" || name == "unexpected" {
                out.extend(owned);
            }
        }
    }
}

/// The alias `name` of one of the three error types, from a `type` item's
/// right-hand side.
fn type_alias(name: &syn::Ident, ty: &Type) -> Option<(String, String)> {
    let Type::Path(path) = ty else { return None };
    let last = path.path.segments.last()?;
    let target = last.ident.unraw().to_string();
    (path.qself.is_none() && last.arguments.is_none() && alias_needle(&target).is_some())
        .then(|| (name.unraw().to_string(), target))
}

/// Every name a file binds to one of the three error types, by `type` alias
/// or `use` rename, in any scope.
#[derive(Default)]
struct Aliases(BTreeMap<String, String>);

impl Aliases {
    fn add_use(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => self.add_use(&path.tree),
            UseTree::Group(group) => group.items.iter().for_each(|item| self.add_use(item)),
            UseTree::Rename(rename) => {
                let target = rename.ident.unraw().to_string();
                if alias_needle(&target).is_some() {
                    self.0.insert(rename.rename.unraw().to_string(), target);
                }
            }
            UseTree::Name(_) | UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for Aliases {
    fn visit_item_type(&mut self, item: &'ast ItemType) {
        self.0.extend(type_alias(&item.ident, &item.ty));
        visit::visit_item_type(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast ImplItemType) {
        self.0.extend(type_alias(&item.ident, &item.ty));
        visit::visit_impl_item_type(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.add_use(&item.tree);
    }
}

fn punct(tree: Option<&TokenTree>, ch: char) -> bool {
    matches!(tree, Some(TokenTree::Punct(p)) if p.as_char() == ch)
}

fn ident(tree: Option<&TokenTree>) -> Option<String> {
    match tree {
        Some(TokenTree::Ident(id)) => Some(id.unraw().to_string()),
        _ => None,
    }
}

/// Whether the tokens after the `From` at `at` are `<String>`, `<a::String>`,
/// `<&str>` or `<&'a str>`, with an optional turbofish `::`.
fn bridge_tokens_at(trees: &[TokenTree], at: usize) -> bool {
    let tree = |i: usize| trees.get(i);
    let mut i = at.saturating_add(1);
    if punct(tree(i), ':') && punct(tree(i.saturating_add(1)), ':') {
        i = i.saturating_add(2);
    }
    if !punct(tree(i), '<') {
        return false;
    }
    i = i.saturating_add(1);
    if punct(tree(i), '&') {
        i = i.saturating_add(1);
        if punct(tree(i), '\'') {
            i = i.saturating_add(2);
        }
        if ident(tree(i)).as_deref() == Some("mut") {
            i = i.saturating_add(1);
        }
        return ident(tree(i)).as_deref() == Some("str") && punct(tree(i.saturating_add(1)), '>');
    }
    loop {
        let Some(name) = ident(tree(i)) else {
            return false;
        };
        let next = i.saturating_add(1);
        if punct(tree(next), ':') && punct(tree(next.saturating_add(1)), ':') {
            i = next.saturating_add(2);
            continue;
        }
        return name == "String" && punct(tree(next), '>');
    }
}

/// The `a::b::c` identifier path that ends at `trees[at]`.
fn token_path_ending_at(trees: &[TokenTree], at: usize) -> Vec<String> {
    let mut names = Vec::new();
    let Some(last) = ident(trees.get(at)) else {
        return names;
    };
    names.push(last);
    let mut end = at;
    loop {
        let colons = end.checked_sub(2).and_then(|first| trees.get(first..end));
        let owner = end.checked_sub(3).and_then(|i| ident(trees.get(i)));
        match (colons, owner) {
            (Some([TokenTree::Punct(a), TokenTree::Punct(b)]), Some(owner))
                if a.as_char() == ':' && b.as_char() == ':' =>
            {
                names.insert(0, owner);
                end = end.saturating_sub(3);
            }
            _ => break,
        }
    }
    names
}

/// The census count and the `(fn, needle)` sites of one file's production syntax.
#[derive(Default)]
struct Scan {
    /// The functions enclosing the node being visited, innermost last.
    functions: Vec<String>,
    /// The self type of each enclosing `impl`, innermost last; `None` when it
    /// is not a plain path.
    impl_self: Vec<Option<String>>,
    /// How many patterns enclose the node being visited.
    in_pattern: usize,
    /// The file's aliases of the three error types, alias to type.
    aliases: BTreeMap<String, String>,
    bridges: usize,
    sites: Vec<(String, &'static str)>,
}

impl Scan {
    fn function(&self) -> String {
        self.functions
            .last()
            .map_or_else(|| OUTSIDE_FN.to_owned(), Clone::clone)
    }

    fn record_site(&mut self, names: &[String]) {
        if self.in_pattern > 0 {
            return;
        }
        let mut resolved = names.to_vec();
        if let (Some(first), Some(Some(self_ty))) = (resolved.first_mut(), self.impl_self.last())
            && first == "Self"
        {
            first.clone_from(self_ty);
        }
        let owner_at = resolved.len().checked_sub(2);
        if let Some(owner) = owner_at.and_then(|at| resolved.get_mut(at))
            && let Some(target) = self.aliases.get(owner.as_str())
        {
            owner.clone_from(target);
        }
        self.record_needle(site_needle(&resolved));
    }

    fn record_needle(&mut self, needle: Option<&'static str>) {
        if let Some(needle) = needle {
            let function = self.function();
            self.sites.push((function, needle));
        }
    }

    /// Scans a macro body for the census and site shapes, naming the
    /// function whose braced body follows `fn name`.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let mut pending_fn: Option<String> = None;
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => {
                    let body = if group.delimiter() == Delimiter::Brace {
                        pending_fn.take()
                    } else {
                        None
                    };
                    let named = body.is_some();
                    if let Some(name) = body {
                        self.functions.push(name);
                    }
                    self.scan_tokens(group.stream());
                    if named {
                        self.functions.pop();
                    }
                }
                TokenTree::Ident(id) => {
                    let name = id.unraw().to_string();
                    let after_fn = at
                        .checked_sub(1)
                        .is_some_and(|before| ident(trees.get(before)).as_deref() == Some("fn"));
                    if after_fn {
                        pending_fn = Some(name);
                        continue;
                    }
                    if name == "From" && bridge_tokens_at(&trees, at) {
                        self.bridges = self.bridges.saturating_add(1);
                    }
                    let continues = punct(trees.get(at.saturating_add(1)), ':')
                        && punct(trees.get(at.saturating_add(2)), ':');
                    if !continues {
                        let names = token_path_ending_at(&trees, at);
                        self.record_site(&names);
                    }
                }
                TokenTree::Punct(p) => {
                    if p.as_char() == ';' {
                        pending_fn = None;
                    }
                }
                TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_attribute(&mut self, _attr: &'ast Attribute) {}

    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_item(self, item);
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

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if cfg_test_only(trait_item_attrs(item)) {
            return;
        }
        if let TraitItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let self_ty = match &*item.self_ty {
            Type::Path(path) if path.qself.is_none() => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.unraw().to_string()),
            _ => None,
        };
        self.impl_self.push(self_ty);
        visit::visit_item_impl(self, item);
        self.impl_self.pop();
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let mut needles = Vec::new();
        use_needles(&item.tree, None, &mut needles);
        for needle in needles {
            self.record_needle(Some(needle));
        }
    }

    fn visit_pat(&mut self, pat: &'ast Pat) {
        self.in_pattern = self.in_pattern.saturating_add(1);
        visit::visit_pat(self, pat);
        self.in_pattern = self.in_pattern.saturating_sub(1);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_item_fn(self, item);
        self.functions.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_impl_item_fn(self, item);
        self.functions.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_trait_item_fn(self, item);
        self.functions.pop();
    }

    fn visit_field(&mut self, field: &'ast Field) {
        if !cfg_test_only(&field.attrs) {
            visit::visit_field(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast Variant) {
        if !cfg_test_only(&variant.attrs) {
            visit::visit_variant(self, variant);
        }
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast FieldValue) {
        if !cfg_test_only(&field.attrs) {
            visit::visit_field_value(self, field);
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

    fn visit_path(&mut self, path: &'ast Path) {
        self.bridges = self.bridges.saturating_add(bridge_segments(path));
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.unraw().to_string())
            .collect();
        self.record_site(&names);
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The scan of `src`; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its error bridges cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut found = Scan::default();
    if let Ok(file) = &parsed {
        let mut aliases = Aliases::default();
        aliases.visit_file(file);
        found.aliases = aliases.0;
        found.visit_file(file);
    }
    found
}

/// Every file of `sources` whose bridge count differs from `table`.
fn census_violations(sources: &[(String, String)], table: &[(&str, usize)]) -> Vec<String> {
    let expected: BTreeMap<&str, usize> = table.iter().copied().collect();
    let mut out = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, src) in sources {
        let found = scan(name, src).bridges;
        if found > 0 {
            seen.insert(name.as_str(), found);
        }
    }
    for (file, found) in &seen {
        match expected.get(file) {
            Some(count) if count == found => {}
            Some(count) => out.push(format!("{file}: expects {count} bridge(s), found {found}")),
            None => out.push(format!("{file}: {found} unlisted bridge(s)")),
        }
    }
    for (file, count) in &expected {
        if !seen.contains_key(file) {
            out.push(format!("{file}: expects {count} bridge(s), found 0"));
        }
    }
    out
}

/// Every unlisted site of `sources`, and every `ledger` entry whose count differs.
fn site_violations(sources: &[(String, String)], ledger: &[Unclassified]) -> Vec<String> {
    let mut found: BTreeMap<(String, String, &'static str), usize> = BTreeMap::new();
    for (name, src) in sources {
        for (function, needle) in scan(name, src).sites {
            let seen = found.entry((name.clone(), function, needle)).or_insert(0);
            *seen = seen.saturating_add(1);
        }
    }
    let mut out = Vec::new();
    for ((file, function, needle), seen) in &found {
        let listed = ledger.iter().find(|e| {
            e.file == file.as_str() && e.function == function.as_str() && e.needle == *needle
        });
        match listed {
            Some(entry) if entry.count == *seen => {}
            Some(entry) => out.push(format!(
                "{file}: {function}: {needle} expects {}, found {seen}",
                entry.count
            )),
            None => out.push(format!("{file}: {function}: {needle} unlisted ({seen})")),
        }
    }
    for entry in ledger {
        let key = (
            entry.file.to_owned(),
            entry.function.to_owned(),
            entry.needle,
        );
        if !found.contains_key(&key) {
            out.push(format!(
                "{}: {}: {} expects {}, found 0",
                entry.file, entry.function, entry.needle, entry.count
            ));
        }
    }
    out
}

fn sources(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(name, src)| ((*name).to_owned(), (*src).to_owned()))
        .collect()
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must catch or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn every_bridge_shape_is_counted() {
    let src = r#"
impl From<String> for A { fn from(m: String) -> Self { A } }
impl<'a> From<&'a str> for A { fn from(m: &'a str) -> Self { A } }
fn b<E: From<String>>() {}
fn c<E>() where E: std::convert::From<std::string::String> {}
fn d(m: String) -> A { From::<String>::from(m) }
fn e<E: From<&'static str>>(m: &'static str) -> E { <E as From<&str>>::from(m) }
m! { impl From<String> for B {} fn f<E: From<&str>>() {} }
"#;
    assert_eq!(scan("fixture", src).bridges, 9);
}

#[test]
fn other_conversions_comments_and_strings_are_not_bridges() {
    let src = r#"
/// From<String> in a doc comment.
// From<String> in a line comment.
impl From<u8> for A { fn from(_: u8) -> Self { A } }
impl From<Vec<String>> for A { fn from(_: Vec<String>) -> Self { A } }
impl From<Box<str>> for A { fn from(_: Box<str>) -> Self { A } }
impl FromIpeError for String { fn from_ipe_error(e: IpeError) -> Self { e.to_ipe_string() } }
fn g() -> &'static str { "From<String>" }
m! { "From<String>" From<u8> }
"#;
    assert_eq!(scan("fixture", src).bridges, 0);
}

#[test]
fn every_site_shape_is_keyed_by_its_function() {
    let src = r#"
fn a(m: String) -> IpeError { IpeError::unexpected(m) }
impl K { fn b(self) -> IpeErrorKind { match self { _ => crate::IpeErrorKind::Unexpected } } }
fn c(m: String) -> KernelFailure { crate::error::KernelFailure::Unexpected(m) }
fn d(m: String) -> IpeError { ipe_error_unexpected(m) }
const X: IpeErrorKind = IpeErrorKind::Unexpected;
m! { fn e(m: String) -> IpeError { IpeError::unexpected(m) } }
impl IpeError { fn f(m: String) -> Self { Self::unexpected(m) } }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("a".to_owned(), "IpeError::unexpected"),
        ("b".to_owned(), "IpeErrorKind::Unexpected"),
        ("c".to_owned(), "KernelFailure::Unexpected"),
        ("d".to_owned(), "ipe_error_unexpected"),
        (OUTSIDE_FN.to_owned(), "IpeErrorKind::Unexpected"),
        ("e".to_owned(), "IpeError::unexpected"),
        ("f".to_owned(), "IpeError::unexpected"),
    ];
    assert_eq!(found, expected);
}

#[test]
fn self_alias_and_import_shapes_are_sites_and_patterns_are_not() {
    let src = r#"
impl From<ProcessRefusal> for KernelFailure {
    fn from(r: ProcessRefusal) -> Self { match r { _ => Self::Unexpected(String::new()) } }
}
impl KernelFailure {
    fn message(&self) -> &str { match self { Self::Unexpected(m) | KernelFailure::Decode(m) => m } }
}
impl crate::error::IpeError { fn g(m: String) -> Self { Self::unexpected(m) } }
impl Other { fn h() -> Self { Self::Unexpected } }
m! { fn i() -> KernelFailure { Self::Unexpected(String::new()) } }
fn j(k: IpeErrorKind) -> bool { matches!(k, IpeErrorKind::Unexpected) }
fn k(k: IpeErrorKind) -> bool { if let IpeErrorKind::Unexpected = k { true } else { false } }
use crate::error::KernelFailure::*;
use crate::error::{IpeErrorKind::{Io, Unexpected as Odd}, KernelFailure as Kf};
use crate::error::IpeError as IpeError;
type Ek = crate::IpeErrorKind;
fn l() -> Kf { Kf::Unexpected(String::new()) }
fn m() -> Ek { Ek::Unexpected }
impl Kf { fn n() -> Self { Self::Unexpected(String::new()) } }
fn o() { type Late = crate::error::IpeError; }
fn p() -> Late { Late::unexpected(String::new()) }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("from".to_owned(), "KernelFailure::Unexpected"),
        ("g".to_owned(), "IpeError::unexpected"),
        ("i".to_owned(), "Self::Unexpected"),
        ("j".to_owned(), "IpeErrorKind::Unexpected"),
        (OUTSIDE_FN.to_owned(), "KernelFailure::Unexpected"),
        (OUTSIDE_FN.to_owned(), "IpeErrorKind::Unexpected"),
        ("l".to_owned(), "KernelFailure::Unexpected"),
        ("m".to_owned(), "IpeErrorKind::Unexpected"),
        ("n".to_owned(), "KernelFailure::Unexpected"),
        ("p".to_owned(), "IpeError::unexpected"),
    ];
    assert_eq!(found, expected);
}

#[test]
fn test_only_code_is_dropped_and_production_after_it_is_scanned() {
    let src = r#"
#[cfg(test)]
mod tests {
    impl From<String> for A {}
    fn t(m: String) -> IpeError { IpeError::unexpected(m) }
}
fn p(m: String) -> IpeError {
    #[cfg(test)]
    let _ = IpeError::unexpected(m.clone());
    IpeError::unexpected(m)
}
#[cfg(not(test))]
impl From<&str> for A {}
"#;
    let found = scan("fixture", src);
    assert_eq!(found.bridges, 1);
    assert_eq!(found.sites, vec![("p".to_owned(), "IpeError::unexpected")]);
}

#[test]
fn the_census_is_exact_per_file() {
    let files = sources(&[
        (
            "a.rs",
            "impl From<String> for A {} fn f<E: From<&str>>() {}",
        ),
        ("b.rs", "fn g() {}"),
    ]);
    assert_eq!(
        census_violations(&files, &[("a.rs", 2)]),
        Vec::<String>::new()
    );
    assert_eq!(
        census_violations(&files, &[("a.rs", 3)]),
        vec!["a.rs: expects 3 bridge(s), found 2"]
    );
    assert_eq!(
        census_violations(&files, &[]),
        vec!["a.rs: 2 unlisted bridge(s)"]
    );
    assert_eq!(
        census_violations(&files, &[("a.rs", 2), ("b.rs", 1)]),
        vec!["b.rs: expects 1 bridge(s), found 0"]
    );
}

#[test]
fn an_unlisted_moved_or_stale_site_is_red() {
    let entry = |function: &'static str| Unclassified {
        file: "x.rs",
        function,
        needle: "IpeError::unexpected",
        count: 1,
        reason: "fixture",
    };
    let here = sources(&[(
        "x.rs",
        "fn a(m: String) -> IpeError { IpeError::unexpected(m) }",
    )]);
    assert_eq!(site_violations(&here, &[entry("a")]), Vec::<String>::new());
    assert_eq!(
        site_violations(&here, &[]),
        vec!["x.rs: a: IpeError::unexpected unlisted (1)"]
    );
    let moved = sources(&[(
        "x.rs",
        "fn b(m: String) -> IpeError { IpeError::unexpected(m) }",
    )]);
    assert_eq!(
        site_violations(&moved, &[entry("a")]),
        vec![
            "x.rs: b: IpeError::unexpected unlisted (1)",
            "x.rs: a: IpeError::unexpected expects 1, found 0",
        ]
    );
    let gone = sources(&[("x.rs", "fn a() {}")]);
    assert_eq!(
        site_violations(&gone, &[entry("a")]),
        vec!["x.rs: a: IpeError::unexpected expects 1, found 0"]
    );
    let twice = sources(&[(
        "x.rs",
        "fn a(m: String) -> (IpeError, IpeError) { (IpeError::unexpected(m.clone()), IpeError::unexpected(m)) }",
    )]);
    assert_eq!(
        site_violations(&twice, &[entry("a")]),
        vec!["x.rs: a: IpeError::unexpected expects 1, found 2"]
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = scan("fixture", "impl From<String> for {");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// The runtime sources, after checking the walk read the files the ledgers name.
fn runtime_sources() -> Vec<(String, String)> {
    let root = e2e_support::manifest_dir!().join("src");
    let found = rust_sources(&root);
    for required in [
        "error.rs",
        "js_port.rs",
        "config_decode.rs",
        "csv.rs",
        "encoding.rs",
        "regex_kernel.rs",
        "url.rs",
        "uuid_kernel.rs",
    ] {
        assert!(
            found.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    found
}

#[test]
fn from_string_census_is_exact() {
    let found = census_violations(&runtime_sources(), TRANSITIONAL_FROM_STRING);
    assert!(
        found.is_empty(),
        "the `From<String>` / `From<&str>` bridge census changed. A converted file builds \
         each failure through its typed sink (`FromIpeError`, `FromDecodeFailure`, \
         `FromLimitExceeded`, `FromUnavailable`) and shrinks its row in \
         `TRANSITIONAL_FROM_STRING`; a new bridge is refused:\n{}",
        found.join("\n")
    );
}

#[test]
fn unclassified_sites_are_ledgered() {
    let found = site_violations(&runtime_sources(), UNCLASSIFIED_SITES);
    assert!(
        found.is_empty(),
        "every production `Unexpected` must be listed in `UNCLASSIFIED_SITES` with its \
         reason, and every listed site must still exist; a failure with a specific \
         cause names that kind instead:\n{}",
        found.join("\n")
    );
    assert!(
        UNCLASSIFIED_SITES
            .iter()
            .all(|entry| !entry.reason.is_empty()),
        "every ledgered site names its reason"
    );
}

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
//!   pattern builds nothing and is not a site. A qualified-self head
//!   `<T>::` (position 0) counts as the owner `T`.
//!
//! Aliases are followed crate-wide: every `type` alias and `use` rename of
//! every scanned file is one edge in a single map, resolved to a fixpoint, so
//! an alias chain (`type B = A; type A = KernelFailure;`) or an alias
//! re-exported from another file still names its type. A `use` importing
//! `Unexpected`/`unexpected` by name, rename or glob from one of the three
//! types makes the bare name (or a module path ending in it) a site where it
//! is built.
//!
//! Inside a macro body the same token shapes count, `<T>::` included, and
//! `fn name { … }` names the function. A metavariable owner (`$t::Unexpected`)
//! may stand for any of the three types, so it is a site of its own needle. Attributes (doc comments) are not code. A `#[cfg(…)]` proven
//! test-only removes exactly the node it is attached to.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprPath, ExprStruct, Field, FieldValue, GenericArgument, ImplItem,
    ImplItemFn, ImplItemType, Item, ItemFn, ItemImpl, ItemType, ItemUse, Macro, Pat, Path,
    PathArguments, QSelf, Stmt, TraitItem, TraitItemFn, Type, TypePath, UseTree, Variant,
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
    ("jwt.rs", 2),
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

/// The needle a `$t::Unexpected` in a macro body is recorded under: the
/// metavariable can stand for any of the three error types.
const METAVAR_UNEXPECTED: &str = "$meta::Unexpected";

/// The needle a `$t::unexpected` in a macro body is recorded under.
const METAVAR_UNEXPECTED_FN: &str = "$meta::unexpected";

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
        (meta, "unexpected") if meta.starts_with('$') => Some(METAVAR_UNEXPECTED_FN),
        (meta, "Unexpected") if meta.starts_with('$') => Some(METAVAR_UNEXPECTED),
        _ => None,
    }
}

/// The canonical name of `name` if it is one of the three error types.
fn error_type(name: &str) -> Option<&'static str> {
    match name {
        "IpeError" => Some("IpeError"),
        "KernelFailure" => Some("KernelFailure"),
        "IpeErrorKind" => Some("IpeErrorKind"),
        _ => None,
    }
}

/// The needle the error type `ty` builds.
fn type_needle(ty: &str) -> Option<&'static str> {
    match ty {
        "IpeError" => Some("IpeError::unexpected"),
        "KernelFailure" => Some("KernelFailure::Unexpected"),
        "IpeErrorKind" => Some("IpeErrorKind::Unexpected"),
        _ => None,
    }
}

/// The bare name a glob import of the error type `ty` brings into scope.
fn glob_name(ty: &str) -> &'static str {
    if ty == "IpeError" {
        "unexpected"
    } else {
        "Unexpected"
    }
}

fn is_unexpected(name: &str) -> bool {
    name == "Unexpected" || name == "unexpected"
}

/// The last identifier of a plain type path, through groups and parens.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.unraw().to_string()),
        Type::Group(group) => type_name(&group.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        _ => None,
    }
}

/// The owner a qualified-self path `<T>::x` puts before its segments.
///
/// It is the last identifier of `T` when the `qself` stands at position 0;
/// `<T as Trait>::x` names the trait's item, not `T`'s.
fn qself_owner(qself: &QSelf) -> Option<String> {
    if qself.position == 0 {
        type_name(&qself.ty)
    } else {
        None
    }
}

/// A `use` that imports `Unexpected`/`unexpected` from `owner`.
struct Import {
    /// The type (or alias) the name is imported from.
    owner: String,
    /// The name it is bound to, or `None` for a glob.
    bound: Option<String>,
}

/// The raw alias edges of every scanned source.
///
/// Each `type` alias and `use` rename adds an edge whatever it names, and each
/// import of the `Unexpected` name is kept. Edges are keyed by name alone,
/// across files and scopes, so an alias re-exported from one file and used in
/// another resolves; a name bound twice stands for every target it is bound
/// to.
#[derive(Default)]
struct AliasEdges {
    /// Each alias name to the names it stands for.
    edges: BTreeMap<String, BTreeSet<String>>,
    imports: Vec<Import>,
    /// The self type of each enclosing `impl`, innermost last.
    impl_self: Vec<Option<String>>,
}

impl AliasEdges {
    fn edge(&mut self, alias: String, target: String) {
        if alias != target {
            self.edges.entry(alias).or_default().insert(target);
        }
    }

    fn import(&mut self, owner: Option<&str>, bound: Option<String>) {
        if let Some(owner) = owner {
            self.imports.push(Import {
                owner: owner.to_owned(),
                bound,
            });
        }
    }

    fn add_use(&mut self, tree: &UseTree, owner: Option<&str>) {
        match tree {
            UseTree::Path(path) => {
                let next = path.ident.unraw().to_string();
                self.add_use(&path.tree, Some(&next));
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.add_use(item, owner);
                }
            }
            UseTree::Glob(_) => self.import(owner, None),
            UseTree::Name(name) => {
                let name = name.ident.unraw().to_string();
                if is_unexpected(&name) {
                    self.import(owner, Some(name));
                }
            }
            UseTree::Rename(rename) => {
                let ident = rename.ident.unraw().to_string();
                let alias = rename.rename.unraw().to_string();
                if is_unexpected(&ident) {
                    return self.import(owner, Some(alias));
                }
                let target = if ident == "self" {
                    owner.map(ToOwned::to_owned)
                } else {
                    Some(ident)
                };
                if let Some(target) = target {
                    self.edge(alias, target);
                }
            }
        }
    }

    fn add_type(&mut self, name: &syn::Ident, ty: &Type) {
        match ty {
            Type::Path(path) if path.qself.is_none() => {
                let Some(last) = path.path.segments.last() else {
                    return;
                };
                if !last.arguments.is_none() {
                    return;
                }
                let mut target = last.ident.unraw().to_string();
                if target == "Self"
                    && let Some(Some(self_ty)) = self.impl_self.last()
                {
                    target.clone_from(self_ty);
                }
                self.edge(name.unraw().to_string(), target);
            }
            Type::Group(group) => self.add_type(name, &group.elem),
            Type::Paren(paren) => self.add_type(name, &paren.elem),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for AliasEdges {
    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        self.impl_self.push(type_name(&item.self_ty));
        visit::visit_item_impl(self, item);
        self.impl_self.pop();
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        self.add_type(&item.ident, &item.ty);
        visit::visit_item_type(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast ImplItemType) {
        self.add_type(&item.ident, &item.ty);
        visit::visit_impl_item_type(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.add_use(&item.tree, None);
    }
}

/// Every name reachable from `start` over `edges`, `start` included.
fn reach<'e>(edges: &'e BTreeMap<String, BTreeSet<String>>, start: &'e str) -> BTreeSet<&'e str> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut todo: Vec<&str> = vec![start];
    while let Some(name) = todo.pop() {
        if seen.insert(name) {
            todo.extend(edges.get(name).into_iter().flatten().map(String::as_str));
        }
    }
    seen
}

/// The alias edges resolved to a fixpoint.
///
/// It records which error types each alias stands for, and which needle each
/// bare imported name builds.
#[derive(Default)]
struct Resolved {
    /// Each alias to the error types it reaches.
    types: BTreeMap<String, BTreeSet<&'static str>>,
    /// Each bare name (an imported `Unexpected`, or an alias reaching one) to
    /// the needles it builds.
    bare: BTreeMap<String, BTreeSet<&'static str>>,
}

impl Resolved {
    fn of(raw: &AliasEdges) -> Self {
        let mut resolved = Self::default();
        for alias in raw.edges.keys() {
            let reached: BTreeSet<&'static str> = reach(&raw.edges, alias)
                .into_iter()
                .filter_map(error_type)
                .collect();
            if !reached.is_empty() {
                resolved.types.insert(alias.clone(), reached);
            }
        }
        let mut direct: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
        for import in &raw.imports {
            for ty in resolved.owner_types(&import.owner) {
                let bound = import
                    .bound
                    .clone()
                    .unwrap_or_else(|| glob_name(ty).to_owned());
                direct.entry(bound).or_default().extend(type_needle(ty));
            }
        }
        let names: BTreeSet<&String> = raw.edges.keys().chain(direct.keys()).collect();
        for name in names {
            let needles: BTreeSet<&'static str> = reach(&raw.edges, name)
                .into_iter()
                .filter_map(|reached| direct.get(reached))
                .flatten()
                .copied()
                .collect();
            if !needles.is_empty() {
                resolved.bare.insert(name.clone(), needles);
            }
        }
        resolved
    }

    /// The error types `owner` names: itself if it is one, and every type an
    /// alias of that name reaches.
    fn owner_types(&self, owner: &str) -> BTreeSet<&'static str> {
        let mut out: BTreeSet<&'static str> = error_type(owner).into_iter().collect();
        out.extend(self.types.get(owner).into_iter().flatten().copied());
        out
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

/// Whether `trees[at - 2]` and `trees[at - 1]` are the two colons of a `::`.
fn colons_before(trees: &[TokenTree], at: usize) -> bool {
    at.checked_sub(2)
        .is_some_and(|first| punct(trees.get(first), ':'))
        && at
            .checked_sub(1)
            .is_some_and(|second| punct(trees.get(second), ':'))
}

/// The name of the identifier at `trees[at]`, spelled `$name` when a `$`
/// precedes it (a macro metavariable; `$crate` stays `crate`), and the index
/// the name starts at.
fn token_name_at(trees: &[TokenTree], at: usize) -> Option<(String, usize)> {
    let name = ident(trees.get(at))?;
    let dollar = at
        .checked_sub(1)
        .filter(|before| punct(trees.get(*before), '$'));
    Some(match dollar {
        Some(start) if name != "crate" => (format!("${name}"), start),
        Some(start) => (name, start),
        None => (name, at),
    })
}

/// The owner of a qualified-self `<a::T>` whose closing `>` is `trees[gt]`:
/// the last identifier of the path inside the angle brackets.
fn token_qself_ending_at(trees: &[TokenTree], gt: usize) -> Option<String> {
    if !punct(trees.get(gt), '>') {
        return None;
    }
    let (owner, mut start) = token_name_at(trees, gt.checked_sub(1)?)?;
    while colons_before(trees, start) {
        let colons = start.checked_sub(2)?;
        match colons
            .checked_sub(1)
            .and_then(|at| token_name_at(trees, at))
        {
            Some((_, segment)) => start = segment,
            None => {
                start = colons;
                break;
            }
        }
    }
    let lt = start.checked_sub(1)?;
    punct(trees.get(lt), '<').then_some(owner)
}

/// The `a::b::c` identifier path that ends at `trees[at]`.
///
/// A `<T>::` head contributes `T`, and a metavariable segment is spelled
/// `$name`.
fn token_path_ending_at(trees: &[TokenTree], at: usize) -> Vec<String> {
    let Some((last, mut start)) = token_name_at(trees, at) else {
        return Vec::new();
    };
    let mut names = vec![last];
    while colons_before(trees, start) {
        let Some(before) = start.checked_sub(3) else {
            break;
        };
        if let Some((owner, owner_start)) = token_name_at(trees, before) {
            names.insert(0, owner);
            start = owner_start;
            continue;
        }
        if let Some(owner) = token_qself_ending_at(trees, before) {
            names.insert(0, owner);
        }
        break;
    }
    names
}

/// The census count and the `(fn, needle)` sites of one file's production syntax.
struct Scan<'r> {
    /// The functions enclosing the node being visited, innermost last.
    functions: Vec<String>,
    /// The self type of each enclosing `impl`, innermost last; `None` when it
    /// is not a plain path.
    impl_self: Vec<Option<String>>,
    /// How many patterns enclose the node being visited.
    in_pattern: usize,
    /// The crate-wide aliases resolved to a fixpoint.
    aliases: &'r Resolved,
    bridges: usize,
    sites: Vec<(String, &'static str)>,
}

impl<'r> Scan<'r> {
    const fn new(aliases: &'r Resolved) -> Self {
        Self {
            functions: Vec::new(),
            impl_self: Vec::new(),
            in_pattern: 0,
            aliases,
            bridges: 0,
            sites: Vec::new(),
        }
    }

    fn function(&self) -> String {
        self.functions
            .last()
            .map_or_else(|| OUTSIDE_FN.to_owned(), Clone::clone)
    }

    /// The needle the path `names` builds, after `Self` and alias resolution.
    fn needle_of(&self, names: &[String]) -> Option<&'static str> {
        let mut resolved = names.to_vec();
        if let (Some(first), Some(Some(self_ty))) = (resolved.first_mut(), self.impl_self.last())
            && first == "Self"
        {
            first.clone_from(self_ty);
        }
        if let Some(needle) = site_needle(&resolved) {
            return Some(needle);
        }
        let owner_at = resolved.len().checked_sub(2);
        if let Some(at) = owner_at
            && let Some(owner) = resolved.get(at).cloned()
        {
            for ty in self.aliases.owner_types(&owner) {
                if let Some(slot) = resolved.get_mut(at) {
                    ty.clone_into(slot);
                }
                if let Some(needle) = site_needle(&resolved) {
                    return Some(needle);
                }
            }
        }
        let (last, head) = resolved.split_last()?;
        let through_module = head
            .last()
            .is_none_or(|owner| owner.starts_with(|c: char| c.is_ascii_lowercase()));
        if !through_module {
            return None;
        }
        self.aliases.bare.get(last)?.first().copied()
    }

    fn record_site(&mut self, names: &[String]) {
        if self.in_pattern > 0 {
            return;
        }
        let needle = self.needle_of(names);
        self.record_needle(needle);
    }

    /// Counts the bridges of `path` and records it as a site, with `owner`
    /// (a qualified-self head) before its segments.
    fn scan_path(&mut self, path: &Path, owner: Option<String>) {
        self.bridges = self.bridges.saturating_add(bridge_segments(path));
        let names: Vec<String> = owner
            .into_iter()
            .chain(
                path.segments
                    .iter()
                    .map(|segment| segment.ident.unraw().to_string()),
            )
            .collect();
        self.record_site(&names);
        visit::visit_path(self, path);
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

impl<'ast> Visit<'ast> for Scan<'_> {
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
        self.impl_self.push(type_name(&item.self_ty));
        visit::visit_item_impl(self, item);
        self.impl_self.pop();
    }

    fn visit_item_use(&mut self, _item: &'ast ItemUse) {}

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
        self.scan_path(path, None);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        match qualified(node.qself.as_ref()) {
            Some((qself, owner)) => {
                self.visit_qself(qself);
                self.scan_path(&node.path, Some(owner));
            }
            None => visit::visit_expr_path(self, node),
        }
    }

    fn visit_expr_struct(&mut self, node: &'ast ExprStruct) {
        match qualified(node.qself.as_ref()) {
            Some((qself, owner)) => {
                self.visit_qself(qself);
                self.scan_path(&node.path, Some(owner));
                for field in &node.fields {
                    self.visit_field_value(field);
                }
                if let Some(rest) = &node.rest {
                    self.visit_expr(rest);
                }
            }
            None => visit::visit_expr_struct(self, node),
        }
    }

    fn visit_type_path(&mut self, node: &'ast TypePath) {
        match qualified(node.qself.as_ref()) {
            Some((qself, owner)) => {
                self.visit_qself(qself);
                self.scan_path(&node.path, Some(owner));
            }
            None => visit::visit_type_path(self, node),
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// A qualified-self head at position 0 and the owner it names.
fn qualified(qself: Option<&QSelf>) -> Option<(&QSelf, String)> {
    let qself = qself?;
    qself_owner(qself).map(|owner| (qself, owner))
}

/// One file's census count and `(fn, needle)` sites.
#[derive(Default)]
struct Found {
    bridges: usize,
    sites: Vec<(String, &'static str)>,
}

/// The scan of every source against one crate-wide alias map; a source that
/// does not parse fails.
fn scan_all(sources: &[(String, String)]) -> Vec<(String, Found)> {
    let mut files = Vec::new();
    for (name, src) in sources {
        let parsed = syn::parse_file(src);
        assert!(
            parsed.is_ok(),
            "{name}: does not parse as Rust, so its error bridges cannot be counted: {:?}",
            parsed.as_ref().err().map(ToString::to_string)
        );
        if let Ok(file) = parsed {
            files.push((name.clone(), file));
        }
    }
    let mut edges = AliasEdges::default();
    for (_, file) in &files {
        edges.visit_file(file);
    }
    let aliases = Resolved::of(&edges);
    files
        .iter()
        .map(|(name, file)| {
            let mut scan = Scan::new(&aliases);
            scan.visit_file(file);
            let found = Found {
                bridges: scan.bridges,
                sites: scan.sites,
            };
            (name.clone(), found)
        })
        .collect()
}

/// The scan of the single source `src`.
fn scan(name: &str, src: &str) -> Found {
    scan_all(&[(name.to_owned(), src.to_owned())])
        .pop()
        .map(|(_, found)| found)
        .unwrap_or_default()
}

/// Every file of `sources` whose bridge count differs from `table`.
fn census_violations(sources: &[(String, String)], table: &[(&str, usize)]) -> Vec<String> {
    let expected: BTreeMap<&str, usize> = table.iter().copied().collect();
    let mut out = Vec::new();
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (name, found) in scan_all(sources) {
        if found.bridges > 0 {
            seen.insert(name, found.bridges);
        }
    }
    for (file, found) in &seen {
        match expected.get(file.as_str()) {
            Some(count) if count == found => {}
            Some(count) => out.push(format!("{file}: expects {count} bridge(s), found {found}")),
            None => out.push(format!("{file}: {found} unlisted bridge(s)")),
        }
    }
    for (file, count) in &expected {
        if !seen.contains_key(*file) {
            out.push(format!("{file}: expects {count} bridge(s), found 0"));
        }
    }
    out
}

/// Every unlisted site of `sources`, and every `ledger` entry whose count differs.
fn site_violations(sources: &[(String, String)], ledger: &[Unclassified]) -> Vec<String> {
    let mut found: BTreeMap<(String, String, &'static str), usize> = BTreeMap::new();
    for (name, scanned) in scan_all(sources) {
        for (function, needle) in scanned.sites {
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
fn q(m: String) -> KernelFailure { Unexpected(m) }
fn r() -> IpeErrorKind { Odd }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("from".to_owned(), "KernelFailure::Unexpected"),
        ("g".to_owned(), "IpeError::unexpected"),
        ("i".to_owned(), "Self::Unexpected"),
        ("j".to_owned(), "IpeErrorKind::Unexpected"),
        ("l".to_owned(), "KernelFailure::Unexpected"),
        ("m".to_owned(), "IpeErrorKind::Unexpected"),
        ("n".to_owned(), "KernelFailure::Unexpected"),
        ("p".to_owned(), "IpeError::unexpected"),
        ("q".to_owned(), "KernelFailure::Unexpected"),
        ("r".to_owned(), "IpeErrorKind::Unexpected"),
    ];
    assert_eq!(found, expected);
}

#[test]
fn a_qualified_self_owner_is_a_site() {
    let src = r#"
impl KernelFailure { fn a(m: String) -> Self { <Self>::Unexpected(m) } }
fn b(m: String) -> KernelFailure { <KernelFailure>::Unexpected(m) }
fn c(m: String) -> IpeError { <crate::error::IpeError>::unexpected(m) }
fn d(m: String) -> KernelFailure { <KernelFailure>::Unexpected { 0: m } }
fn e(m: String) -> IpeError { <IpeError as Tr>::unexpected(m) }
m! { fn f() -> IpeErrorKind { <crate::IpeErrorKind>::Unexpected } }
m! { fn g(m: String) -> KernelFailure { <Self>::Unexpected(m) } }
fn h(k: KernelFailure) -> bool { if let <KernelFailure>::Unexpected(_) = k { true } else { false } }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("a".to_owned(), "KernelFailure::Unexpected"),
        ("b".to_owned(), "KernelFailure::Unexpected"),
        ("c".to_owned(), "IpeError::unexpected"),
        ("d".to_owned(), "KernelFailure::Unexpected"),
        ("f".to_owned(), "IpeErrorKind::Unexpected"),
        ("g".to_owned(), "Self::Unexpected"),
    ];
    assert_eq!(found, expected);
}

#[test]
fn an_alias_chain_resolves_to_a_fixpoint() {
    let src = r#"
type A = KernelFailure;
type B = A;
use self::B as C;
use crate::error::IpeErrorKind as D;
use self::D as E;
use crate::error::{self as err, IpeError::{self as Ie}};
type F = Ie;
type Loop1 = Loop2;
type Loop2 = Loop1;
impl KernelFailure { type Me = Self; }
fn a() -> B { B::Unexpected(String::new()) }
fn b() -> C { C::Unexpected(String::new()) }
fn c() -> E { E::Unexpected }
fn d(m: String) -> F { F::unexpected(m) }
fn e() -> Loop1 { Loop1::Unexpected }
fn f(m: String) -> KernelFailure { Me::Unexpected(m) }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("a".to_owned(), "KernelFailure::Unexpected"),
        ("b".to_owned(), "KernelFailure::Unexpected"),
        ("c".to_owned(), "IpeErrorKind::Unexpected"),
        ("d".to_owned(), "IpeError::unexpected"),
        ("f".to_owned(), "KernelFailure::Unexpected"),
    ];
    assert_eq!(found, expected);
}

#[test]
fn an_alias_from_another_file_is_resolved() {
    let files = sources(&[
        ("a.rs", "pub type Kf = crate::error::KernelFailure;"),
        (
            "b.rs",
            "use crate::a::Kf; fn f(m: String) -> Kf { Kf::Unexpected(m) }",
        ),
        ("c.rs", "pub use crate::a::Kf as Kf2;"),
        ("d.rs", "fn g(m: String) -> Kf2 { Kf2::Unexpected(m) }"),
        (
            "e.rs",
            "pub use crate::error::IpeErrorKind::Unexpected as Boom;",
        ),
        ("f.rs", "fn h() -> IpeErrorKind { crate::e::Boom }"),
    ]);
    let found: Vec<(String, Vec<(String, &str)>)> = scan_all(&files)
        .into_iter()
        .filter(|(_, found)| !found.sites.is_empty())
        .map(|(name, found)| (name, found.sites))
        .collect();
    let site = |name: &str, function: &str, needle: &'static str| {
        (name.to_owned(), vec![(function.to_owned(), needle)])
    };
    assert_eq!(
        found,
        vec![
            site("b.rs", "f", "KernelFailure::Unexpected"),
            site("d.rs", "g", "KernelFailure::Unexpected"),
            site("f.rs", "h", "IpeErrorKind::Unexpected"),
        ]
    );
}

#[test]
fn a_metavariable_owner_in_a_macro_is_a_site() {
    let src = r#"
macro_rules! boom { ($t:ty, $m:expr) => { $t::Unexpected($m) }; }
macro_rules! fail { ($t:path) => { fn inner() -> IpeError { $t::unexpected(String::new()) } }; }
macro_rules! wrapped { ($t:ty) => { <$t>::Unexpected }; }
macro_rules! krate { () => { $crate::Unexpected }; }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        (OUTSIDE_FN.to_owned(), METAVAR_UNEXPECTED),
        ("inner".to_owned(), METAVAR_UNEXPECTED_FN),
        (OUTSIDE_FN.to_owned(), METAVAR_UNEXPECTED),
    ];
    assert_eq!(found, expected);
}

#[test]
fn a_bare_imported_unexpected_is_a_site_where_it_is_built() {
    let src = r#"
mod a { pub use crate::error::KernelFailure::*; }
use crate::error::IpeErrorKind::{Unexpected as Odd};
use self::Odd as Odder;
fn f(m: String) -> KernelFailure { Unexpected(m) }
fn g() -> IpeErrorKind { Odd }
fn h() -> IpeErrorKind { Odder }
fn i(m: String) -> KernelFailure { a::Unexpected(m) }
fn j(k: KernelFailure) -> bool { if let Unexpected(_) = k { true } else { false } }
fn k() -> Other { Other::Unexpected }
m! { fn l(m: String) -> KernelFailure { Unexpected(m) } }
"#;
    let found = scan("fixture", src).sites;
    let expected: Vec<(String, &str)> = vec![
        ("f".to_owned(), "KernelFailure::Unexpected"),
        ("g".to_owned(), "IpeErrorKind::Unexpected"),
        ("h".to_owned(), "IpeErrorKind::Unexpected"),
        ("i".to_owned(), "KernelFailure::Unexpected"),
        ("l".to_owned(), "KernelFailure::Unexpected"),
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

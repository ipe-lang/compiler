//! The backend renders a generic's bounds; it never adds one.
//!
//! Every bound a generic or row variable carries is finalized by the lowerer
//! before the cross-call fixpoint carries it to callers. A bound the backend
//! adds while rendering is invisible to that fixpoint, so a caller forwarding
//! the variable into the function emits a clause missing it and the emitted
//! Rust fails to build. The scan parses every `.rs` file under the backend's
//! `src/` with `syn` and refuses, outside test items, every `BoundSet` builder
//! call (`.with_send()` and its siblings) and every path through `BoundSet`
//! (`BoundSet::STATIC`, `ipe_ir::BoundSet::with_send(b)`), through any
//! `use … as` rename of `BoundSet`.
//!
//! It refuses, too, every string literal naming an auto-trait (`Send`,
//! `Sync`, `'static`) as a word anywhere in it — `"Send"`, `" + Send"`,
//! `"R{n}: Send + {}"` alike — outside the functions that own that spelling
//! ([`RENDERERS`]), so no clause can carry an auto-trait its finalized set
//! does not. A carrier literal (`dyn Fn(..) + Send + Sync + 'static`, the
//! `FN{i}: Fn(..) -> R + Send + …` slot) spells the bounds of the trait object
//! it names and passes, but only for words after its `dyn Fn` / `: Fn(` head.
//! Inside one macro call, the fragments touching a literal's edge or a `{…}`
//! placeholder must not join into an auto-trait name either, so
//! `concat!("Se", "nd")` and `format!("{}end", "S")` are refused. Doc
//! attributes are prose. Macro bodies are walked token by token under the same
//! rules. A file that does not parse is red, never skipped. The `BoundSet`
//! allow-list is empty and stays empty.

use std::collections::BTreeSet;
use std::path::Path;

use proc_macro2::{Span, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, UseTree};

/// The `BoundSet` builder methods: each adds a bound.
const BUILDERS: &[&str] = &[
    "with_add",
    "with_clone",
    "with_copy",
    "with_eq",
    "with_hash",
    "with_interpolable",
    "with_ipe_row",
    "with_mul",
    "with_ord",
    "with_ord_total",
    "with_send",
    "with_show",
    "with_sql_param",
    "with_static",
    "with_sub",
    "with_sync",
];

/// The bound-set type's own name.
const BOUND_SET: &str = "BoundSet";

/// The auto-trait bounds a generic clause renders from a `BoundSet`.
const AUTO_TRAITS: &[&str] = &["'static", "Send", "Sync"];

/// The functions that own an auto-trait's spelling, by file relative to the
/// backend's `src/`.
///
/// `render_auto_traits` renders a generic's finalized `BoundSet`;
/// `carrier_static_bounds` renders the `'static` a type declaration's stored
/// `dyn Fn` carrier forces on its own parameters, which no caller obliges.
const RENDERERS: &[(&str, &str)] = &[
    ("emit_expr/func.rs", "render_auto_traits"),
    ("emit_types.rs", "carrier_static_bounds"),
];

/// The byte spans of the words in `text`: runs of `[A-Za-z0-9_]`, with a
/// leading `'` kept when a letter follows it (`'static`).
fn words(text: &str) -> Vec<(usize, usize)> {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut spans = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        let lifetime = c == '\'' && chars.peek().is_some_and(|(_, n)| n.is_ascii_alphabetic());
        if is_word(c) || lifetime {
            let mut end = at.saturating_add(c.len_utf8());
            while let Some((next_at, next)) = chars.peek().copied() {
                if !is_word(next) {
                    break;
                }
                end = next_at.saturating_add(next.len_utf8());
                chars.next();
            }
            spans.push((at, end));
        }
    }
    spans
}

/// Where a carrier literal's head (`dyn Fn`, `: Fn(`) ends, if `text` has one.
fn carrier_head(text: &str) -> Option<usize> {
    ["dyn Fn", ": Fn("]
        .iter()
        .filter_map(|head| text.find(head).map(|at| at.saturating_add(head.len())))
        .min()
}

/// The auto-trait words of `text` outside a carrier's bounds.
fn auto_trait_words(text: &str) -> Vec<String> {
    let head = carrier_head(text);
    words(text)
        .into_iter()
        .filter(|(start, _)| head.is_none_or(|h| *start < h))
        .filter_map(|(start, end)| text.get(start..end))
        .filter(|word| AUTO_TRAITS.contains(word))
        .map(str::to_owned)
        .collect()
}

/// The words of `text` touching its edge or a `{…}` placeholder: the pieces
/// a macro could join into one word.
fn edge_words(text: &str, into: &mut BTreeSet<String>) {
    let mut segments = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        let (before, after) = rest.split_at(open);
        if after.starts_with("{{") {
            segments.push(before);
            rest = after.get(2..).unwrap_or_default();
            continue;
        }
        segments.push(before);
        rest = after.find('}').map_or("", |close| {
            after.get(close.saturating_add(1)..).unwrap_or_default()
        });
    }
    segments.push(rest);
    for segment in segments {
        for (start, end) in words(segment) {
            if (start == 0 || end == segment.len())
                && let Some(word) = segment.get(start..end)
            {
                into.insert(word.to_owned());
            }
        }
    }
}

/// Whether `name` splits into two or more pieces, each one of `pieces`.
fn joins_into(name: &str, pieces: &BTreeSet<String>) -> bool {
    let len = name.len();
    let mut reach = vec![false; len.saturating_add(1)];
    if let Some(first) = reach.first_mut() {
        *first = true;
    }
    for end in 1..=len {
        let reachable = pieces.iter().any(|piece| {
            piece.len() < len
                && end >= piece.len()
                && name.get(end.saturating_sub(piece.len())..end) == Some(piece.as_str())
                && reach
                    .get(end.saturating_sub(piece.len()))
                    .copied()
                    .unwrap_or(false)
        });
        if let Some(slot) = reach.get_mut(end) {
            *slot = reachable;
        }
    }
    reach.last().copied().unwrap_or(false)
}

/// The string-literal values of a macro body, at any depth.
fn macro_literals(stream: TokenStream, into: &mut Vec<String>) {
    for tree in stream {
        match tree {
            TokenTree::Group(group) => macro_literals(group.stream(), into),
            TokenTree::Literal(literal) => {
                if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                    into.push(text.value());
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
}

/// One refused site: the line and what it spells.
type Site = (usize, String);

/// Whether `attrs` gate their item to test builds: `#[test]` or `#[cfg(test)]`.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || matches!(
                &attr.meta,
                Meta::List(list) if list.path.is_ident("cfg") && list.tokens.to_string() == "test"
            )
    })
}

/// The names `BoundSet` goes by in one file, renames included.
struct Names(BTreeSet<String>);

impl Names {
    /// Record every `use … BoundSet as X` rename under `tree`.
    fn renames(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => self.renames(&path.tree),
            UseTree::Rename(rename) => {
                if self.0.contains(&rename.ident.unraw().to_string()) {
                    self.0.insert(rename.rename.unraw().to_string());
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.renames(item);
                }
            }
            UseTree::Name(_) | UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for Names {
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.renames(&item.tree);
    }
}

/// The refused sites of one parsed file.
struct Sites {
    /// The names `BoundSet` goes by.
    names: BTreeSet<String>,
    /// The sites found so far.
    found: Vec<Site>,
    /// The renderer this file owns, if any.
    renderer: Option<&'static str>,
    /// How deep the walk is inside the renderer's function.
    in_renderer: usize,
}

impl Sites {
    /// Record `text` at `span`.
    fn hit(&mut self, span: Span, text: String) {
        self.found.push((span.start().line, text));
    }

    /// Refuse the string literal `value` at `span` when it names an
    /// auto-trait outside a renderer.
    fn literal(&mut self, span: Span, value: &str) {
        if self.in_renderer == 0 {
            for word in auto_trait_words(value) {
                self.hit(span, format!("{word} in {value:?}"));
            }
        }
    }

    /// Refuse a macro call whose literal fragments join into an auto-trait.
    fn joined_fragments(&mut self, mac: &syn::Macro) {
        if self.in_renderer > 0 {
            return;
        }
        let mut literals = Vec::new();
        macro_literals(mac.tokens.clone(), &mut literals);
        let mut pieces = BTreeSet::new();
        for literal in literals.iter().filter(|l| carrier_head(l).is_none()) {
            edge_words(literal, &mut pieces);
        }
        for name in AUTO_TRAITS {
            if joins_into(name, &pieces) {
                let span = mac
                    .path
                    .segments
                    .last()
                    .map_or_else(Span::call_site, |segment| segment.ident.span());
                self.hit(span, format!("{name} joined from {literals:?}"));
            }
        }
    }

    /// Walk `item`'s body with `visit`, inside the renderer when `name` is it.
    fn function(&mut self, name: &proc_macro2::Ident, visit: impl FnOnce(&mut Self)) {
        let renderer = self.renderer.is_some_and(|owner| name.unraw() == owner);
        if renderer {
            self.in_renderer = self.in_renderer.saturating_add(1);
        }
        visit(self);
        if renderer {
            self.in_renderer = self.in_renderer.saturating_sub(1);
        }
    }

    /// Whether `ident` names the bound-set type.
    fn is_bound_set(&self, ident: &proc_macro2::Ident) -> bool {
        self.names.contains(&ident.unraw().to_string())
    }

    /// Refuse a `use` that reaches inside `BoundSet` (`use BoundSet::STATIC`).
    fn use_tree(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => {
                if self.is_bound_set(&path.ident) {
                    self.hit(path.ident.span(), format!("use {}::…", path.ident));
                } else {
                    self.use_tree(&path.tree);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item);
                }
            }
            UseTree::Name(_) | UseTree::Rename(_) | UseTree::Glob(_) => {}
        }
    }

    /// Walk a macro body: `BoundSet ::` or `. with_*` is refused there too.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Ident(ident) => {
                    let next = trees.get(at.saturating_add(1));
                    let previous = at.checked_sub(1).and_then(|p| trees.get(p));
                    let path_follows =
                        matches!(next, Some(TokenTree::Punct(p)) if p.as_char() == ':');
                    let method_call =
                        matches!(previous, Some(TokenTree::Punct(p)) if p.as_char() == '.');
                    let name = ident.unraw().to_string();
                    if self.is_bound_set(ident) && path_follows {
                        self.hit(ident.span(), format!("{name}::…"));
                    } else if method_call && BUILDERS.contains(&name.as_str()) {
                        self.hit(ident.span(), format!(".{name}()"));
                    }
                }
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(literal) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&literal.to_string()) {
                        self.literal(literal.span(), &text.value());
                    }
                }
                TokenTree::Punct(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !is_test_only(&item.attrs) {
            self.function(&item.sig.ident, |sites| visit::visit_item_fn(sites, item));
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_impl(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !is_test_only(&item.attrs) {
            self.function(&item.sig.ident, |sites| {
                visit::visit_impl_item_fn(sites, item);
            });
        }
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_const(self, item);
        }
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_static(self, item);
        }
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if !is_test_only(&item.attrs) {
            self.use_tree(&item.tree);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.unraw().to_string();
        if BUILDERS.contains(&name.as_str()) {
            self.hit(call.method.span(), format!(".{name}()"));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let mut segments = path.segments.iter().peekable();
        while let Some(segment) = segments.next() {
            if segments.peek().is_some() && self.is_bound_set(&segment.ident) {
                let text = path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");
                self.hit(segment.ident.span(), text);
                break;
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.literal(lit.span(), &lit.value());
    }

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if !attr.path().is_ident("doc") {
            visit::visit_attribute(self, attr);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.joined_fragments(mac);
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The refused production sites of `src`, the file at `rel` under the
/// backend's `src/`.
///
/// # Errors
///
/// A message when `src` does not parse, so it cannot be judged.
fn scan_source(rel: &str, src: &str) -> Result<Vec<Site>, String> {
    let file =
        syn::parse_file(src).map_err(|e| format!("does not parse, so it cannot be judged: {e}"))?;
    let mut names = Names(BTreeSet::from([BOUND_SET.to_owned()]));
    names.visit_file(&file);
    let mut sites = Sites {
        names: names.0,
        found: Vec::new(),
        renderer: RENDERERS
            .iter()
            .find(|(file, _)| *file == rel)
            .map(|(_, owner)| *owner),
        in_renderer: 0,
    };
    sites.visit_file(&file);
    Ok(sites.found)
}

/// Scan every `.rs` file under `dir`, naming each refused site by its path
/// relative to `root`; a `tests` directory is test code.
///
/// # Errors
///
/// A message naming the directory or file that cannot be read or parsed.
fn scan_dir(root: &Path, dir: &Path, found: &mut Vec<String>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths = Vec::new();
    for entry in entries {
        paths.push(entry.map_err(|e| format!("{}: {e}", dir.display()))?.path());
    }
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests") {
                continue;
            }
            scan_dir(root, &path, found)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let src =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let sites = scan_source(&rel, &src).map_err(|e| format!("{rel}: {e}"))?;
            found.extend(
                sites
                    .into_iter()
                    .map(|(line, text)| format!("{rel}:{line}: {text}")),
            );
        }
    }
    Ok(())
}

/// The backend's non-test code builds no bound: every generic clause renders
/// the lowerer's finalized set verbatim.
#[test]
fn backend_adds_no_bound_after_the_fixpoint() -> Result<(), String> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = Vec::new();
    scan_dir(&root, &root, &mut found)?;
    assert!(
        found.is_empty(),
        "the backend must render bounds, never build them — move each into the \
         lowerer's signature or body rules before the fixpoint:\n{}",
        found.join("\n")
    );
    Ok(())
}

/// Whether `src` holds at least one refused site.
fn refused(src: &str) -> bool {
    scan_source("sample.rs", src).is_ok_and(|sites| !sites.is_empty())
}

/// Whether `src`, read as the file at `rel`, holds no refused site.
fn passes(rel: &str, src: &str) -> bool {
    scan_source(rel, src).is_ok_and(|sites| sites.is_empty())
}

#[test]
fn a_builder_method_call_is_refused() {
    assert!(refused(
        "fn f(bounds: BoundSet) -> BoundSet { bounds.with_send() }"
    ));
}

#[test]
fn a_bound_set_constant_is_refused() {
    assert!(refused("fn f() -> BoundSet { BoundSet::STATIC }"));
}

#[test]
fn a_qualified_builder_call_is_refused() {
    assert!(refused(
        "fn f(b: ipe_ir::BoundSet) -> ipe_ir::BoundSet { ipe_ir::BoundSet::with_send(b) }"
    ));
}

#[test]
fn a_renamed_bound_set_path_is_refused() {
    assert!(refused(
        "use ipe_ir::BoundSet as B;\nfn f() -> B { B::STATIC }"
    ));
}

#[test]
fn a_use_into_bound_set_is_refused() {
    assert!(refused("use ipe_ir::BoundSet::STATIC;\nfn f() {}"));
}

#[test]
fn a_builder_inside_a_macro_is_refused() {
    assert!(refused(
        "fn f(b: BoundSet) -> Vec<BoundSet> { vec![b.with_static()] }"
    ));
    assert!(refused("fn f() -> Vec<BoundSet> { vec![BoundSet::SEND] }"));
}

#[test]
fn an_unparsable_file_is_red() {
    assert!(scan_source("sample.rs", "fn f( {").is_err());
}

#[test]
fn rendering_and_prose_pass() {
    let src = "use ipe_ir::BoundSet;\n\
               // A comment naming `BoundSet::STATIC` is prose.\n\
               /// So is `bounds.with_send()` in a doc.\n\
               fn render(bounds: BoundSet) -> bool { bounds.has_send() }\n\
               fn space(s: Shape) -> Shape { s.with_space(0) }\n";
    assert!(passes("sample.rs", src));
}

#[test]
fn test_items_are_not_judged() {
    let src = "#[cfg(test)]\nmod tests {\n    fn f() -> BoundSet { BoundSet::STATIC.with_send() }\n}\n\
               #[test]\nfn g() { let _ = BoundSet::SEND; }\n";
    assert!(passes("sample.rs", src));
}

#[test]
fn an_auto_trait_literal_pushed_into_a_clause_is_refused() {
    assert!(refused(
        "fn f(bounds: &mut Vec<String>) { bounds.push(\"Send\".to_owned()); }"
    ));
    assert!(refused(
        "fn f(bounds: &mut Vec<&str>) { bounds.push(\"Send\"); }"
    ));
    assert!(refused(
        "fn f() -> String { \"'static + Sync\".to_owned() }"
    ));
    assert!(refused("fn f() -> String { format!(\"Sync\") }"));
}

#[test]
fn the_renderer_spells_auto_traits_only_in_its_own_file() {
    let renderer = "fn render_auto_traits() -> Vec<String> {\n\
                    \x20   vec![\"'static\".to_owned(), \"Send\".to_owned()]\n}\n";
    assert!(passes("emit_expr/func.rs", renderer));
    assert!(refused(renderer));
    assert!(!passes(
        "emit_expr/func.rs",
        "fn render_row() -> String { \"Send\".to_owned() }"
    ));
}

#[test]
fn a_carrier_type_spelling_its_bounds_passes() {
    let src = "fn carrier() -> String {\n\
               \x20   format!(\"::std::sync::Arc<dyn Fn(i64) + Send + Sync + 'static>\")\n}\n\
               fn clause() -> String { format!(\"FN1: Fn(i64) -> R + Send + Sync + 'static\") }\n\
               fn life() -> &'static str { \"Sender\" }\n";
    assert!(passes("sample.rs", src));
}

#[test]
fn an_auto_trait_word_inside_a_longer_literal_is_refused() {
    assert!(refused(
        "fn f(entries: &mut Vec<String>, n: usize, rest: &str) { entries.push(format!(\"R{n}: Send + {}\", rest)); }"
    ));
    assert!(refused(
        "fn f(bounds: &mut String) { bounds.push_str(\" + Send\"); }"
    ));
}

#[test]
fn an_auto_trait_joined_from_macro_fragments_is_refused() {
    assert!(refused(
        "fn f() -> &'static str { concat!(\"Se\", \"nd\") }"
    ));
    assert!(refused("fn f() -> String { format!(\"{}end\", \"S\") }"));
}

#[test]
fn a_word_before_a_carrier_head_is_refused() {
    assert!(refused(
        "fn f() -> String { \"Send + Box<dyn Fn(i64) -> i64>\".to_owned() }"
    ));
}

#[test]
fn a_doc_attribute_naming_an_auto_trait_is_prose() {
    assert!(passes(
        "sample.rs",
        "/// Renders `Send + 'static` from the finalized set.\nfn f() {}\n"
    ));
}

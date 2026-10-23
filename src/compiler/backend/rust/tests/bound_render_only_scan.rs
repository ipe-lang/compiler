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
//! `use … as` rename of `BoundSet`. Macro bodies are walked token by token
//! under the same rules. A file that does not parse is red, never skipped.
//! The allow-list is empty and stays empty.

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
}

impl Sites {
    /// Record `text` at `span`.
    fn hit(&mut self, span: Span, text: String) {
        self.found.push((span.start().line, text));
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
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Sites {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !is_test_only(&item.attrs) {
            visit::visit_item_fn(self, item);
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
            visit::visit_impl_item_fn(self, item);
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

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The refused production sites of `src`.
///
/// # Errors
///
/// A message when `src` does not parse, so it cannot be judged.
fn scan_source(src: &str) -> Result<Vec<Site>, String> {
    let file =
        syn::parse_file(src).map_err(|e| format!("does not parse, so it cannot be judged: {e}"))?;
    let mut names = Names(BTreeSet::from([BOUND_SET.to_owned()]));
    names.visit_file(&file);
    let mut sites = Sites {
        names: names.0,
        found: Vec::new(),
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
                .display()
                .to_string();
            let src =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let sites = scan_source(&src).map_err(|e| format!("{rel}: {e}"))?;
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
    scan_source(src).is_ok_and(|sites| !sites.is_empty())
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
    assert!(scan_source("fn f( {").is_err());
}

#[test]
fn rendering_and_prose_pass() {
    let src = "use ipe_ir::BoundSet;\n\
               // A comment naming `BoundSet::STATIC` is prose.\n\
               /// So is `bounds.with_send()` in a doc.\n\
               fn render(bounds: BoundSet) -> bool { bounds.has_send() }\n\
               fn space(s: Shape) -> Shape { s.with_space(0) }\n";
    assert!(scan_source(src).is_ok_and(|sites| sites.is_empty()));
}

#[test]
fn test_items_are_not_judged() {
    let src = "#[cfg(test)]\nmod tests {\n    fn f() -> BoundSet { BoundSet::STATIC.with_send() }\n}\n\
               #[test]\nfn g() { let _ = BoundSet::SEND; }\n";
    assert!(scan_source(src).is_ok_and(|sites| sites.is_empty()));
}

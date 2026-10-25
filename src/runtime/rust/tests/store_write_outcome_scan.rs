//! Session-store write-outcome scan.
//!
//! Every write a session store performs returns a value the caller must
//! match: the store's production code discards no value through a `let _`
//! binding, and the outcome types `Installed` and `Deleted` (`web/store.rs`)
//! and `Checkpoint` (`web/mod.rs`) are `#[must_use]` and carry no
//! `PartialEq`, so no caller can compare one outcome and let the others fall
//! through.
//!
//! Each source is parsed with `syn`; a `#[cfg(...)]` proven test-only removes
//! exactly the node it is attached to. A macro body is scanned token by token
//! with no `#[cfg(test)]` honoured, and `let` followed by `_` there counts.
#![cfg(not(target_arch = "wasm32"))]

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ImplItem, Item, ItemEnum, ItemImpl, Local, Macro, Pat, Stmt, TraitItem,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The `let _` bindings production `web/store.rs` admits.
const ADMITTED_WILD_LETS: usize = 0;

/// What the production syntax of one file shows.
#[derive(Default)]
struct Scan {
    /// Every `let _` binding, as a short description.
    wild_lets: Vec<String>,
    /// Every enum as (name, `#[must_use]`, derives `PartialEq`).
    enums: Vec<(String, bool, bool)>,
    /// Every type a hand-written `PartialEq` impl names as its self type.
    partial_eq_impls: Vec<String>,
}

/// Whether `pat` binds nothing: `_`, or `_: T`.
fn is_wild(pat: &Pat) -> bool {
    if let Pat::Type(typed) = pat {
        is_wild(&typed.pat)
    } else {
        matches!(pat, Pat::Wild(_))
    }
}

/// Whether `tokens` names `PartialEq` at any group depth.
fn names_partial_eq(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Group(group) => names_partial_eq(group.stream()),
        TokenTree::Ident(id) => id == "PartialEq",
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// Whether `attrs` derive `PartialEq`.
fn derives_partial_eq(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| names_partial_eq(list.tokens.clone()))
    })
}

impl Scan {
    /// Records every `let` followed by `_` in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut after_let = false;
        for tree in tokens {
            after_let = match tree {
                TokenTree::Group(group) => {
                    self.scan_tokens(group.stream());
                    false
                }
                TokenTree::Ident(id) => {
                    if after_let && id == "_" {
                        self.wild_lets.push("let _ in a macro body".to_owned());
                    }
                    id == "let"
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => false,
            };
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_item(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
        self.enums.push((
            item.ident.to_string(),
            item.attrs
                .iter()
                .any(|attr| attr.path().is_ident("must_use")),
            derives_partial_eq(&item.attrs),
        ));
        visit::visit_item_enum(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let partial_eq = item.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|seg| seg.ident == "PartialEq")
        });
        if partial_eq
            && let syn::Type::Path(ty) = item.self_ty.as_ref()
            && let Some(last) = ty.path.segments.last()
        {
            self.partial_eq_impls.push(last.ident.to_string());
        }
        visit::visit_item_impl(self, item);
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

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
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

    fn visit_local(&mut self, local: &'ast Local) {
        if is_wild(&local.pat) {
            self.wild_lets.push("let _ binding".to_owned());
        }
        visit::visit_local(self, local);
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

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The scan of the production syntax of `src`; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its write outcomes cannot be proven matched: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut found = Scan::default();
    if let Ok(file) = parsed {
        found.visit_file(&file);
    }
    found
}

/// The violations of the outcome-type rule for `wanted` in `scan`.
fn outcome_type_violations(name: &str, scan: &Scan, wanted: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    for ty in wanted {
        let found: Vec<&(String, bool, bool)> =
            scan.enums.iter().filter(|(n, _, _)| n == ty).collect();
        if found.is_empty() {
            violations.push(format!("{name}: enum {ty} not found"));
        }
        for (_, must_use, partial_eq) in found {
            if !*must_use {
                violations.push(format!("{name}: {ty} is not #[must_use]"));
            }
            if *partial_eq {
                violations.push(format!("{name}: {ty} derives PartialEq"));
            }
        }
        if scan.partial_eq_impls.iter().any(|n| n == ty) {
            violations.push(format!("{name}: {ty} implements PartialEq"));
        }
    }
    violations
}

/// The source of `rel` under the runtime's `src/`.
fn source(sources: &[(String, String)], rel: &str) -> String {
    let found = sources.iter().find(|(name, _)| name == rel);
    assert!(found.is_some(), "the source walk did not read {rel}");
    found.map(|(_, src)| src.clone()).unwrap_or_default()
}

#[test]
fn store_production_code_discards_no_value() {
    let sources = rust_sources(&e2e_support::manifest_dir!().join("src"));
    let store = source(&sources, "web/store.rs");
    let found = scan("web/store.rs", &store).wild_lets;
    assert_eq!(
        found.len(),
        ADMITTED_WILD_LETS,
        "web/store.rs production code discards a value through `let _`; match \
         the write outcome instead: {found:?}"
    );
}

#[test]
fn write_outcomes_are_must_use_and_never_compared() {
    let sources = rust_sources(&e2e_support::manifest_dir!().join("src"));
    let mut violations = outcome_type_violations(
        "web/store.rs",
        &scan("web/store.rs", &source(&sources, "web/store.rs")),
        &["Installed", "Deleted"],
    );
    violations.extend(outcome_type_violations(
        "web/mod.rs",
        &scan("web/mod.rs", &source(&sources, "web/mod.rs")),
        &["Checkpoint"],
    ));
    assert!(
        violations.is_empty(),
        "a write outcome must be #[must_use] and carry no PartialEq: {violations:?}"
    );
}

#[test]
fn a_wild_let_in_production_is_caught() {
    let found = scan(
        "fixture",
        "fn f() { let _ = write(); let _: u8 = g(); m!(let _ = h()); }",
    )
    .wild_lets;
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn a_wild_let_in_test_only_code_is_ignored() {
    let found = scan(
        "fixture",
        "fn f() { let x = write(); drop(x); } \
         #[cfg(test)] mod tests { fn t() { let _ = write(); } }",
    )
    .wild_lets;
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_compared_outcome_is_caught() {
    let derived = scan(
        "fixture",
        "#[must_use] #[derive(Debug, PartialEq)] pub enum Installed { Held }",
    );
    assert_eq!(
        outcome_type_violations("fixture", &derived, &["Installed"]).len(),
        1
    );
    let manual = scan(
        "fixture",
        "#[must_use] #[derive(Debug)] pub enum Deleted { Removed } \
         impl PartialEq for Deleted { fn eq(&self, _: &Self) -> bool { true } }",
    );
    assert_eq!(
        outcome_type_violations("fixture", &manual, &["Deleted"]).len(),
        1
    );
    let unmarked = scan("fixture", "#[derive(Debug)] enum Checkpoint { Stored }");
    assert_eq!(
        outcome_type_violations("fixture", &unmarked, &["Checkpoint"]).len(),
        1
    );
    let missing = scan("fixture", "enum Other { A }");
    assert_eq!(
        outcome_type_violations("fixture", &missing, &["Checkpoint"]).len(),
        1
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    drop(scan("fixture", "fn f( { let _ = g(); }"));
}

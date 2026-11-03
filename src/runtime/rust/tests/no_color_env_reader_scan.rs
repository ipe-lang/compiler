//! `NO_COLOR` reader scan: the environment variable that forces
//! [`crate::color::TermProfile::NoColor`] has exactly one typed reader in
//! production code, [`crate::color::resolve_term_profile`] — the single place
//! `Tui`/`Cli` decide the colour profile. A second independent reader can
//! disagree with the first (e.g. on "present" vs "present and non-empty"),
//! which is the two-readers-of-one-input class the scan guards against.
//!
//! The scan counts, per file, every production-syntax string literal equal to
//! `"NO_COLOR"` and asserts the per-file counts equal [`ADMITTED`] exactly — an
//! unexpected new reader (or a stray second one in an existing file) turns the
//! scan red, never silently passes.
//!
//! Every `.rs` file under `src/` is parsed with `syn`, so comments and doc
//! attributes are never code, and a `#[cfg(test)]`-proven test-only node is
//! pruned before counting.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, ImplItem, Item, Macro, Stmt, TraitItem, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The env var a colour decision reads.
const NO_COLOR_VAR: &str = "NO_COLOR";

/// Every admitted literal naming [`NO_COLOR_VAR`]: file, count.
///
/// `color.rs` is the one intended reader: [`crate::color::resolve_term_profile`],
/// which every `Tui`/`Cli` colour decision reads through its typed
/// [`crate::color::TermProfile`] result.
///
/// `core.rs`'s `eprint_task_error` is a SECOND, pre-existing reader with its own
/// (slightly different: "present at all" vs "present and non-empty") reading of
/// the same var, for the emitted app's top-level task-error printer — a
/// genuinely separate surface from the `Tui`/`Cli` rendering pipeline this scan
/// otherwise closes. It is admitted here, not closed, because `core.rs` is out
/// of this change's file boundary; closing it (routing that printer through
/// `resolve_term_profile` too) is tracked as a follow-up, not silently hidden.
const ADMITTED: &[(&str, usize)] = &[("color.rs", 1), ("core.rs", 1)];

/// The counted literal naming [`NO_COLOR_VAR`] in one file's production syntax.
#[derive(Default, Debug, PartialEq, Eq)]
struct Scan {
    reads: usize,
}

impl Scan {
    fn literal(&mut self, value: &str) {
        if value == NO_COLOR_VAR {
            self.reads = self.reads.saturating_add(1);
        }
    }

    /// Records every counted literal in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
                TokenTree::Literal(lit) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                        self.literal(&text.value());
                    }
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if attr.path().is_ident("doc") {
            return;
        }
        if let syn::Meta::List(list) = &attr.meta {
            self.scan_tokens(list.tokens.clone());
        }
        visit::visit_attribute(self, attr);
    }

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

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.literal(&lit.value());
        visit::visit_lit_str(self, lit);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The counted [`NO_COLOR_VAR`] reads in the production syntax of `src`; a
/// source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its {NO_COLOR_VAR} reads cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut found = Scan::default();
    if let Ok(file) = &parsed {
        found.visit_file(file);
    }
    found
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must count or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_planted_no_color_read_is_counted() {
    let src = r#"
fn resolve() -> bool {
    matches!(crate::system::read_env_var("NO_COLOR"), Ok(v) if !v.is_empty())
}
"#;
    assert_eq!(scan("fixture", src), Scan { reads: 1 });
}

#[test]
fn a_no_color_read_inside_a_macro_body_is_counted() {
    let src = r#"
fn resolve() {
    let _ = format!("{:?}", std::env::var("NO_COLOR"));
}
"#;
    assert_eq!(scan("fixture", src), Scan { reads: 1 });
}

#[test]
fn test_only_code_and_comments_are_not_counted() {
    let src = r#"
/// `NO_COLOR` is prose here.
fn production() {
    // std::env::var("NO_COLOR")
    #[cfg(test)]
    let t = read_env_var("NO_COLOR");
}
#[cfg(test)]
mod tests {
    fn t() { let _ = std::env::var("NO_COLOR"); }
}
"#;
    assert_eq!(scan("fixture", src), Scan { reads: 0 });
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = scan("fixture", "fn resolve( { \"NO_COLOR\" }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// `NO_COLOR` is read only where [`ADMITTED`] says: the one intended reader in
/// `color.rs`, plus the pre-existing, out-of-boundary `core.rs` reader this
/// change does not close. No other file — in particular not `tui/layout.rs`,
/// which used to cache its own independent reader — reads it at all.
#[test]
fn no_color_has_one_reader() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    let mut reads: BTreeMap<String, usize> = BTreeMap::new();
    for (name, src) in &sources {
        let found = scan(name, src);
        if found.reads > 0 {
            reads.insert(name.clone(), found.reads);
        }
    }
    let admitted: BTreeMap<String, usize> = ADMITTED
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        reads, admitted,
        "`{NO_COLOR_VAR}` is read only where ADMITTED says; every `Tui`/`Cli` colour \
         decision must read the typed `TermProfile` `resolve_term_profile` produces, never \
         a second raw read of the env var"
    );
}

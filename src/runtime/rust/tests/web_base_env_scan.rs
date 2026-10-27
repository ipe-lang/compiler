//! Web base-path scan: a web app's base is read from the environment at one
//! site, and no web module writes the environment.
//!
//! A web app's mount base lives in its own router state. A second read of
//! `IPE_WEB_BASE_PATH` is a second source of the base that can disagree with
//! the app's state, and a write lets one app re-base every other app in the
//! process. The scan counts, per file, every production-syntax string literal
//! naming the variable and asserts the counts equal [`ADMITTED`]; under
//! `web/` it also counts every environment-writer identifier
//! ([`ENV_WRITERS`]) and asserts there are none.
//!
//! Every `.rs` file under `src/` is parsed with `syn`, so comments and doc
//! attributes are never code, and a `#[cfg(...)]` proven test-only removes
//! exactly the node it is attached to. A macro body is scanned token by token
//! with no `#[cfg(test)]` honoured.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, Ident, ImplItem, Item, Macro, Stmt, TraitItem, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The variable a standalone app's base is read from.
const BASE_VAR: &str = "IPE_WEB_BASE_PATH";

/// The identifiers that write the process environment.
const ENV_WRITERS: &[&str] = &[
    "set_var",
    "remove_var",
    "locked_set_var",
    "locked_set_var_if_absent",
    "locked_remove_var",
];

/// The directory whose production code never writes the environment.
const WEB_DIR: &str = "web/";

/// Every admitted literal naming [`BASE_VAR`]: file, count.
const ADMITTED: &[(&str, usize)] = &[
    // The parent hands the console child its base at spawn.
    ("web/console_proxy.rs", 1),
    // `MountContext::from_env`: the one read, at a standalone app's start.
    ("web/mod.rs", 1),
];

/// The counted forms in the production syntax of one file.
#[derive(Default, Debug, PartialEq, Eq)]
struct Scan {
    /// String literals naming [`BASE_VAR`].
    base_reads: usize,
    /// Environment-writer identifiers, by name.
    writers: BTreeMap<String, usize>,
}

impl Scan {
    fn literal(&mut self, value: &str) {
        if value.contains(BASE_VAR) {
            self.base_reads = self.base_reads.saturating_add(1);
        }
    }

    fn ident(&mut self, id: &Ident) {
        let name = id.unraw().to_string();
        if ENV_WRITERS.contains(&name.as_str()) {
            let count = self.writers.entry(name).or_insert(0);
            *count = count.saturating_add(1);
        }
    }

    /// Records every counted form in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(id) => self.ident(&id),
                TokenTree::Literal(lit) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                        self.literal(&text.value());
                    }
                }
                TokenTree::Punct(_) => {}
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

    fn visit_ident(&mut self, id: &'ast Ident) {
        self.ident(id);
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

/// The counted forms in the production syntax of `src`; a source that does
/// not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its base reads cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut found = Scan::default();
    if let Ok(file) = &parsed {
        found.visit_file(file);
    }
    found
}

/// `forms` as a counted writer map, for fixture assertions.
fn writers(forms: &[(&str, usize)]) -> BTreeMap<String, usize> {
    forms.iter().map(|(f, n)| ((*f).to_owned(), *n)).collect()
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must count or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_planted_base_read_and_env_write_are_counted() {
    let src = r#"
fn base() -> Option<String> {
    crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/a");
    let raw = crate::system::read_env_var("IPE_WEB_BASE_PATH").ok();
    let f = std::env::remove_var;
    raw
}
"#;
    assert_eq!(
        scan("fixture", src),
        Scan {
            base_reads: 2,
            writers: writers(&[("locked_set_var", 1), ("remove_var", 1)]),
        }
    );
}

#[test]
fn a_base_read_inside_a_macro_body_is_counted() {
    let src = r#"
fn base() {
    let _ = format!("{:?}", std::env::var("IPE_WEB_BASE_PATH"));
    m! { #[cfg(test)] fn t() { locked_remove_var("x") } }
}
"#;
    assert_eq!(
        scan("fixture", src),
        Scan {
            base_reads: 1,
            writers: writers(&[("locked_remove_var", 1)]),
        }
    );
}

#[test]
fn test_only_code_and_comments_are_not_counted() {
    let src = r#"
/// `IPE_WEB_BASE_PATH` is prose, as is `locked_set_var`.
fn production() {
    // locked_set_var("IPE_WEB_BASE_PATH", "/a")
    #[cfg(test)]
    let t = read_env_var("IPE_WEB_BASE_PATH");
}
#[cfg(test)]
mod tests {
    fn t() { crate::system::locked_set_var("IPE_WEB_BASE_PATH", "/a") }
}
#[cfg(not(test))]
fn scanned() -> &'static str { "IPE_WEB_BASE_PATH" }
"#;
    assert_eq!(
        scan("fixture", src),
        Scan {
            base_reads: 1,
            writers: BTreeMap::new(),
        }
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = scan("fixture", "fn base( { \"IPE_WEB_BASE_PATH\" }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// The base is read at its admitted sites only, and no web module writes the
/// environment.
#[test]
fn the_web_base_has_one_source_and_web_never_writes_the_env() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for (required, _) in ADMITTED {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let mut reads: BTreeMap<String, usize> = BTreeMap::new();
    let mut web_writers: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for (name, src) in &sources {
        let found = scan(name, src);
        if found.base_reads > 0 {
            reads.insert(name.clone(), found.base_reads);
        }
        if name.starts_with(WEB_DIR) && !found.writers.is_empty() {
            web_writers.insert(name.clone(), found.writers);
        }
    }
    let admitted: BTreeMap<String, usize> = ADMITTED
        .iter()
        .map(|(file, count)| ((*file).to_owned(), *count))
        .collect();
    assert_eq!(
        reads, admitted,
        "`{BASE_VAR}` is read only where ADMITTED says; a web app takes its base from its own \
         state, never from a second read of the environment"
    );
    assert!(
        web_writers.is_empty(),
        "a web module writes the environment, which re-bases every app in the process: \
         {web_writers:?}"
    );
}

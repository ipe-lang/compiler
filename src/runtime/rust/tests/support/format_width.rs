//! The runtime-width scan shared by the runtime's and the `ipe` crate's
//! `format_width_scan.rs`.
//!
//! A `{:w$}` width or `{:.p$}` precision is a `u16` to the formatter, so a
//! value past 65535 panics it, in release builds too. Production code pads
//! through `repeat` instead. A width or precision argument is admitted only
//! when it names an `ALL_CAPS` const, or a named argument at the same token
//! level binds it to an integer literal or an `ALL_CAPS` const path; a
//! positional `N$` argument is a run-time value and always refused. A `.*`
//! precision is outside this scan.
//!
//! Every macro's tokens are read at every group depth, with no `#[cfg(test)]`
//! honoured inside a macro body, and every string literal there is judged as
//! a format string: a non-format string that spells a run-time width is
//! refused too, since the scan cannot tell the two apart. A node whose `cfg`
//! is proven test-only is skipped, and a source that does not parse fails.

use proc_macro2::{Spacing, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, ForeignItem, ImplItem, Item, Lit, Macro, MetaList,
    Stmt, TraitItem, Variant,
};

use super::cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

/// Whether `name` spells an `ALL_CAPS` const.
fn is_const_name(name: &str) -> bool {
    name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Every width or precision argument the placeholders of `fmt` name, as an
/// identifier or a position, in source order.
pub fn width_arguments(fmt: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut chars = fmt.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '{' {
            continue;
        }
        if chars.next_if_eq(&'{').is_some() {
            continue;
        }
        let placeholder: String = chars.by_ref().take_while(|&c| c != '}').collect();
        let Some((_, spec)) = placeholder.split_once(':') else {
            continue;
        };
        let mut run = String::new();
        for c in spec.chars() {
            if c == '$' && !run.is_empty() {
                let name = run.trim_start_matches(|d: char| d.is_ascii_digit());
                found.push(if name.is_empty() {
                    run.clone()
                } else {
                    name.to_owned()
                });
            }
            if c.is_alphanumeric() || c == '_' {
                run.push(c);
            } else {
                run.clear();
            }
        }
    }
    found
}

/// Whether a named argument's `value` tokens are an integer literal or an
/// `ALL_CAPS` const path.
fn is_fixed_value(value: &[TokenTree]) -> bool {
    match value {
        [TokenTree::Literal(lit)] => lit.to_string().starts_with(|c: char| c.is_ascii_digit()),
        [.., TokenTree::Ident(last)] => {
            is_const_name(&last.to_string())
                && value.iter().all(|t| match t {
                    TokenTree::Ident(_) => true,
                    TokenTree::Punct(p) => p.as_char() == ':',
                    TokenTree::Group(_) | TokenTree::Literal(_) => false,
                })
        }
        _ => false,
    }
}

/// The `name = value` argument one comma-separated `segment` spells, with
/// whether its value is fixed.
fn named_argument(segment: &[TokenTree]) -> Option<(String, bool)> {
    let [TokenTree::Ident(name), TokenTree::Punct(eq), value @ ..] = segment else {
        return None;
    };
    (eq.as_char() == '=' && eq.spacing() == Spacing::Alone)
        .then(|| (name.to_string(), is_fixed_value(value)))
}

/// Every run-time width argument the production syntax of one file takes.
#[derive(Default)]
struct Scan {
    found: Vec<String>,
}

impl Scan {
    /// Judges every string literal of one token level against that level's
    /// named arguments, then each nested group as its own level.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let named: Vec<(String, bool)> = trees
            .split(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == ','))
            .filter_map(named_argument)
            .collect();
        for tree in &trees {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Literal(lit) => {
                    if let Lit::Str(text) = Lit::new(lit.clone()) {
                        for arg in width_arguments(&text.value()) {
                            let fixed = named
                                .iter()
                                .find(|(name, _)| *name == arg)
                                .map_or_else(|| is_const_name(&arg), |(_, fixed)| *fixed);
                            if !fixed {
                                self.found.push(arg);
                            }
                        }
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
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

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if let ForeignItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_foreign_item(self, item);
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

    fn visit_meta_list(&mut self, list: &'ast MetaList) {
        self.scan_tokens(list.tokens.clone());
        visit::visit_meta_list(self, list);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every run-time width or precision argument in the production syntax of
/// `src`; a source that does not parse fails.
pub fn runtime_widths(name: &str, src: &str) -> Vec<String> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so it cannot be proven free of run-time format widths: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.found
}

//! Lower-span scan: lower production code spells no synthetic span.
//!
//! A lowering refusal is reported at the span of the node it lowers, which
//! the helper takes as a parameter. A refusal minted at `Span::DUMMY` (or its
//! spellings `Span::new(0, 0)` and `Span { lo: 0, hi: 0 }`) reaches the user
//! with no caret, so every such spelling outside test-only code is refused,
//! keyed by the function it appears in, except the exact allowlist below.

use std::collections::BTreeMap;

use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Expr, ImplItem, ImplItemFn, Item, ItemFn, Lit, Macro, Member, Token, TraitItem};

use crate::cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};
use crate::source_tree::rust_sources;

/// The lower crate's production source root, relative to this crate's manifest.
const LOWER_SRC: &str = "../compiler/lower/src";

/// The functions that may spell a synthetic span, each with its exact count.
///
/// `same_emitted_type` lowers two type heads only to compare the results; it
/// never reports a refusal, so its span is never shown.
const ALLOWED: &[(&str, usize)] = &[("same_emitted_type", 1)];

/// The key a synthetic span outside every function is counted under.
const OUTSIDE_FN: &str = "<outside every fn>";

/// Whether `path`'s last two segments are `Span` and `last`.
fn ends_with_span(path: &syn::Path, last: &str) -> bool {
    let mut rev = path.segments.iter().rev();
    rev.next().is_some_and(|s| s.ident == last) && rev.next().is_some_and(|s| s.ident == "Span")
}

/// Whether `expr` is the integer literal `0`.
fn is_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(lit) if matches!(&lit.lit, Lit::Int(n) if n.base10_digits() == "0"))
}

/// Whether `expr` itself spells a synthetic span.
fn is_synthetic_span(expr: &Expr) -> bool {
    match expr {
        Expr::Path(p) => ends_with_span(&p.path, "DUMMY"),
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Path(p) if ends_with_span(&p.path, "new"))
                && call.args.len() == 2
                && call.args.iter().all(is_zero)
        }
        Expr::Struct(s) => {
            s.path
                .segments
                .last()
                .is_some_and(|seg| seg.ident == "Span")
                && s.rest.is_none()
                && s.fields.len() == 2
                && s.fields.iter().all(|f| {
                    matches!(&f.member, Member::Named(name) if name == "lo" || name == "hi")
                        && is_zero(&f.expr)
                })
        }
        _ => false,
    }
}

/// Every synthetic span in one file's production syntax, counted per enclosing fn.
#[derive(Default)]
struct Scan {
    fns: Vec<String>,
    hits: BTreeMap<String, usize>,
}

impl Scan {
    fn record(&mut self) {
        let key = self
            .fns
            .last()
            .map_or(OUTSIDE_FN, String::as_str)
            .to_owned();
        let count = self.hits.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        if !cfg_test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.fns.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.fns.pop();
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !cfg_test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.fns.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.fns.pop();
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if !cfg_test_only(trait_item_attrs(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if !cfg_test_only(&field.attrs) {
            visit::visit_field_value(self, field);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(local) => &local.attrs,
            syn::Stmt::Macro(mac) => &mac.attrs,
            syn::Stmt::Item(_) | syn::Stmt::Expr(..) => &[],
        };
        if !cfg_test_only(attrs) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if cfg_test_only(expr_attrs(expr)) {
            return;
        }
        if is_synthetic_span(expr) {
            self.record();
        }
        visit::visit_expr(self, expr);
    }

    /// A macro body that parses as comma-separated expressions is scanned as
    /// such; any other body is scanned token by token for `Span::DUMMY`.
    fn visit_macro(&mut self, mac: &'ast Macro) {
        match mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            Ok(args) => args.iter().for_each(|arg| self.visit_expr(arg)),
            Err(_) => {
                for _ in 0..dummy_token_runs(mac.tokens.clone()) {
                    self.record();
                }
            }
        }
        visit::visit_macro(self, mac);
    }
}

/// How many `Span :: DUMMY` runs `tokens` spells, at every group depth.
fn dummy_token_runs(tokens: proc_macro2::TokenStream) -> usize {
    use proc_macro2::TokenTree;
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let here = trees
        .windows(4)
        .filter(|w| {
            matches!(w, [TokenTree::Ident(span), TokenTree::Punct(a), TokenTree::Punct(b), TokenTree::Ident(dummy)]
                if span == "Span" && a.as_char() == ':' && b.as_char() == ':' && dummy == "DUMMY")
        })
        .count();
    trees.iter().fold(here, |n, tree| match tree {
        TokenTree::Group(group) => n.saturating_add(dummy_token_runs(group.stream())),
        _ => n,
    })
}

/// The synthetic spans in the production syntax of `src`, counted per enclosing fn.
fn synthetic_spans(name: &str, src: &str) -> BTreeMap<String, usize> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so it cannot be proven free of synthetic spans: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.hits
}

/// Every way `hits` departs from `allowed`: a site beyond or below its exact count.
fn departures(hits: &BTreeMap<String, usize>, allowed: &[(&str, usize)]) -> Vec<String> {
    let mut found: Vec<String> = hits
        .iter()
        .filter(|(name, _)| !allowed.iter().any(|(fn_name, _)| fn_name == name))
        .map(|(name, n)| format!("`{name}` spells {n} synthetic span(s)"))
        .collect();
    for (fn_name, want) in allowed {
        let got = hits.get(*fn_name).copied().unwrap_or(0);
        if got != *want {
            found.push(format!(
                "allowlisted `{fn_name}` spells {got} synthetic span(s), not exactly {want}"
            ));
        }
    }
    found
}

/// The hits of a one-file fixture.
fn fixture_hits(src: &str) -> BTreeMap<String, usize> {
    synthetic_spans("fixture", src)
}

#[test]
fn each_spelling_in_a_plain_fn_is_caught() {
    for body in [
        "Span::DUMMY",
        "Span::new(0, 0)",
        "Span { lo: 0, hi: 0 }",
        "vec![Span::DUMMY]",
    ] {
        let src = format!("fn refuse() -> Span {{ {body} }}");
        assert_eq!(
            fixture_hits(&src),
            BTreeMap::from([("refuse".to_owned(), 1)]),
            "`{body}` is a synthetic span"
        );
    }
}

#[test]
fn a_real_span_is_admitted() {
    let src = "fn real(at: Span) -> Span { let _ = Span::new(0, 1); at }";
    assert!(fixture_hits(src).is_empty());
}

#[test]
fn test_only_code_is_not_scanned() {
    let src = r"
#[cfg(test)]
mod tests {
    fn fixture() -> Span { Span::DUMMY }
}
impl Lowerer {
    #[cfg(test)]
    fn helper() -> Span { Span::new(0, 0) }
}
";
    assert!(fixture_hits(src).is_empty());
}

#[test]
fn a_full_path_spelling_is_caught() {
    let src = r"
impl Lowerer {
    fn refuse(&self) -> Diagnostic { unsupported(ipe_diagnostics::Span::DUMMY, Feature::Kernels) }
}
";
    assert_eq!(
        fixture_hits(src),
        BTreeMap::from([("refuse".to_owned(), 1)])
    );
}

#[test]
fn a_stale_allowlist_entry_is_red() {
    let departed = departures(&BTreeMap::new(), ALLOWED);
    assert_eq!(
        departed.len(),
        1,
        "a zero-match entry is stale: {departed:?}"
    );
}

#[test]
fn a_second_hit_in_an_allowlisted_fn_is_red() {
    let src = r"
impl Lowerer {
    fn same_emitted_type(&self) -> bool { lower(Span::DUMMY) == lower(Span::DUMMY) }
}
";
    let departed = departures(&fixture_hits(src), ALLOWED);
    assert_eq!(departed.len(), 1, "two hits exceed the count: {departed:?}");
}

/// Every production source of the lower crate spells a synthetic span only
/// where the allowlist names it, exactly as often.
#[test]
fn lower_production_code_spells_no_synthetic_span() {
    let root = e2e_support::manifest_dir!().join(LOWER_SRC);
    let sources = rust_sources(&root);
    assert!(
        sources.iter().any(|(name, _)| name == "lower.rs"),
        "the source walk did not read lower.rs"
    );
    let mut hits: BTreeMap<String, usize> = BTreeMap::new();
    for (name, src) in &sources {
        for (fn_name, n) in synthetic_spans(name, src) {
            let count = hits.entry(fn_name).or_insert(0);
            *count = count.saturating_add(n);
        }
    }
    let departed = departures(&hits, ALLOWED);
    assert!(
        departed.is_empty(),
        "a lowering refusal takes the span of the node it lowers as a parameter, \
         never a synthetic one:\n{}",
        departed.join("\n")
    );
}

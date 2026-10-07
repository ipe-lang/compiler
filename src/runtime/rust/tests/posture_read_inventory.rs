//! Posture-read inventory: every read of the process posture outside
//! `telemetry.rs` is one of the admitted, closing-direction reads.
//!
//! A dev-only relaxation must open only under a `DevIntent` or `DevSurface`
//! token, which `telemetry.rs` alone mints. A raw posture read anywhere else
//! is how an opening gated by the environment alone would come back, so the
//! scan counts, per file, every production-syntax use of a posture name and
//! asserts the counts equal [`ADMITTED`]. A new read, a dropped read, or a
//! renamed path to one turns the scan red.
//!
//! Every `.rs` file under `src/` but `telemetry.rs` is parsed with `syn`, so
//! comments and string literals are never code, and a `#[cfg(...)]` proven
//! test-only removes exactly the node it is attached to. A node whose `cfg`
//! is not proven test-only is scanned. A macro body is scanned token by token
//! with no `#[cfg(test)]` honoured.
//!
//! Counted forms:
//! - every identifier in [`POSTURE_FNS`] or [`POSTURE_TYPES`], wherever it
//!   stands (call, fn pointer, method, `use`, rename);
//! - `Posture` as a path segment, as `Posture::<next>` when a segment follows
//!   and as bare `Posture` (a type, an import, an alias target) otherwise;
//! - a `use` of `Posture` renamed or followed by a glob or a group, recorded
//!   under its own key, so an alias never hides the reads made through it;
//! - a string literal naming a posture variable ([`POSTURE_VARS`]), in code
//!   or a macro body, so a raw `ENV` read never stands in for the posture;
//! - a `.posture` field access, so a resolved posture is never re-read
//!   through its label or a comparison that names no `Posture` path.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, ForeignItem, Ident, ImplItem, Item, Macro, Path, Stmt,
    TraitItem, UseTree, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The posture functions and token minters `telemetry.rs` defines.
const POSTURE_FNS: &[&str] = &[
    "posture_is_production",
    "production_from_env",
    "dev_intent",
    "dev_surface",
];

/// The posture types counted by name wherever they stand, besides `Posture`.
const POSTURE_TYPES: &[&str] = &["BuildPosture"];

/// The environment variables the posture is parsed from, counted as string
/// literals.
const POSTURE_VARS: &[&str] = &["ENV", "IPE_ENV"];

/// The field a resolved posture is carried in, counted as a field access.
const POSTURE_FIELD: &str = "posture";

/// The posture enum counted as a path segment.
const POSTURE: &str = "Posture";

/// The file that defines every posture read, and is not scanned.
const POSTURE_OWNER: &str = "telemetry.rs";

/// Every admitted posture read outside [`POSTURE_OWNER`]: file, counted form,
/// count. Each closes a surface rather than opening one.
const ADMITTED: &[(&str, &str, usize)] = &[
    // `gate_allows`: a production posture needs an admin credential to mount.
    ("web/console.rs", "Posture", 1),
    ("web/console.rs", "Posture::Production", 1),
    ("web/console.rs", ".posture", 1),
];

/// Every posture read in the production syntax of one file, by counted form.
#[derive(Default)]
struct Scan {
    reads: BTreeMap<String, usize>,
}

impl Scan {
    fn record(&mut self, form: String) {
        let count = self.reads.entry(form).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Records a counted identifier.
    fn ident(&mut self, id: &Ident) {
        let name = id.unraw().to_string();
        if POSTURE_FNS.contains(&name.as_str()) || POSTURE_TYPES.contains(&name.as_str()) {
            self.record(name);
        }
    }

    /// Records a string literal naming a posture variable.
    fn lit_str(&mut self, value: &str) {
        if POSTURE_VARS.contains(&value) {
            self.record(format!("{value:?}"));
        }
    }

    /// Records every counted form in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(id) if id.unraw() == POSTURE => {
                    let next = trees.get(at.saturating_add(3));
                    let colons = matches!(
                        (trees.get(at.saturating_add(1)), trees.get(at.saturating_add(2))),
                        (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                            if a.as_char() == ':' && b.as_char() == ':'
                    );
                    match next {
                        Some(TokenTree::Ident(seg)) if colons => {
                            self.record(format!("{POSTURE}::{}", seg.unraw()));
                        }
                        _ => self.record(POSTURE.to_owned()),
                    }
                }
                TokenTree::Ident(id) => self.ident(id),
                TokenTree::Literal(lit) => {
                    if let Ok(text) = syn::parse_str::<syn::LitStr>(&lit.to_string()) {
                        self.lit_str(&text.value());
                    }
                }
                TokenTree::Punct(_) => {}
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

    fn visit_ident(&mut self, id: &'ast Ident) {
        self.ident(id);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let segments: Vec<&Ident> = path.segments.iter().map(|s| &s.ident).collect();
        for (at, seg) in segments.iter().enumerate() {
            if seg.unraw() == POSTURE {
                match segments.get(at.saturating_add(1)) {
                    Some(next) => self.record(format!("{POSTURE}::{}", next.unraw())),
                    None => self.record(POSTURE.to_owned()),
                }
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        match tree {
            UseTree::Path(p) if p.ident.unraw() == POSTURE => match p.tree.as_ref() {
                UseTree::Name(n) => self.record(format!("{POSTURE}::{}", n.ident.unraw())),
                UseTree::Rename(r) => {
                    self.record(format!("{POSTURE}::{}", r.ident.unraw()));
                    self.record(format!("use {POSTURE}::… as {}", r.rename.unraw()));
                }
                UseTree::Path(_) | UseTree::Glob(_) | UseTree::Group(_) => {
                    self.record(format!("use {POSTURE}::{{…}}"));
                }
            },
            UseTree::Name(n) if n.ident.unraw() == POSTURE => self.record(POSTURE.to_owned()),
            UseTree::Rename(r) if r.ident.unraw() == POSTURE => {
                self.record(POSTURE.to_owned());
                self.record(format!("use {POSTURE} as {}", r.rename.unraw()));
            }
            _ => {}
        }
        visit::visit_use_tree(self, tree);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.lit_str(&lit.value());
        visit::visit_lit_str(self, lit);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member
            && name.unraw() == POSTURE_FIELD
        {
            self.record(format!(".{POSTURE_FIELD}"));
        }
        visit::visit_expr_field(self, field);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every posture read in the production syntax of `src`, by counted form; a
/// source that does not parse fails.
fn posture_reads(name: &str, src: &str) -> BTreeMap<String, usize> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its posture reads cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.reads
}

/// `forms` as a counted map, for fixture assertions.
fn counted(forms: &[(&str, usize)]) -> BTreeMap<String, usize> {
    forms.iter().map(|(f, n)| ((*f).to_owned(), *n)).collect()
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must count or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_path_qualified_posture_call_is_counted() {
    let src = r"
fn production() -> bool {
    crate::telemetry::posture_is_production() || ::ipe_runtime::telemetry::production_from_env()
}
";
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[("posture_is_production", 1), ("production_from_env", 1)])
    );
}

#[test]
fn a_posture_fn_pointer_and_method_are_counted() {
    let src = r"
fn production(x: X) -> bool {
    let f = posture_is_production;
    f() && x.dev_intent(1, 2).is_some()
}
";
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[("posture_is_production", 1), ("dev_intent", 1)])
    );
}

#[test]
fn a_use_alias_is_counted_and_never_hides_its_reads() {
    let src = r"
use crate::telemetry::posture_is_production as open;
use crate::telemetry::Posture as P;
use crate::telemetry::Posture::Dev as D;
use crate::telemetry::Posture::*;
use crate::telemetry::{BuildPosture as B, dev_surface as s};
type Q = crate::telemetry::Posture;
fn production() -> bool { open() }
";
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[
            ("posture_is_production", 1),
            ("Posture", 2),
            ("use Posture as P", 1),
            ("Posture::Dev", 1),
            ("use Posture::… as D", 1),
            ("use Posture::{…}", 1),
            ("BuildPosture", 1),
            ("dev_surface", 1),
        ])
    );
}

#[test]
fn posture_variants_in_expressions_and_patterns_are_counted() {
    let src = r"
fn production(p: telemetry::Posture) -> bool {
    match p {
        Posture::Dev => Posture::from_env() == telemetry::Posture::Production,
        _ => false,
    }
}
";
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[
            ("Posture", 1),
            ("Posture::Dev", 1),
            ("Posture::from_env", 1),
            ("Posture::Production", 1),
        ])
    );
}

#[test]
fn a_posture_read_inside_a_macro_body_is_counted() {
    let src = r#"
fn production() {
    let _ = format!("{}", crate::telemetry::Posture::Dev == x);
    m! { #[cfg(test)] fn t() { production_from_env() } }
}
"#;
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[("Posture::Dev", 1), ("production_from_env", 1)])
    );
}

#[test]
fn test_only_code_strings_and_comments_are_not_counted() {
    let src = r#"
/// `posture_is_production()` is prose.
fn production() {
    // Posture::Dev
    let s = "production_from_env()";
    #[cfg(test)]
    let t = Posture::Production;
    let _ = s;
}
#[cfg(test)]
mod tests {
    fn t() -> bool { crate::telemetry::posture_is_production() }
}
#[cfg(not(test))]
fn scanned() -> bool { dev_surface() }
"#;
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[("dev_surface", 1)])
    );
}

#[test]
fn the_token_gates_are_not_posture_reads() {
    let src = r"
fn production() -> bool {
    crate::telemetry::dev_intent_from_env().is_some()
        && telemetry::dev_surface_from_env().is_none()
}
";
    assert_eq!(posture_reads("fixture", src), BTreeMap::new());
}

// A raw `ENV`/`IPE_ENV` read opens on the environment alone, and a resolved
// posture re-read through its label names no `Posture` path: both counted,
// in code and in a macro body.
#[test]
fn a_raw_posture_variable_read_and_a_posture_field_read_are_counted() {
    let src = r#"
fn open() -> bool {
    crate::system::read_env_var("ENV").as_deref() == Ok("dev")
        || std::env::var("IPE_ENV").is_ok()
        || resolved.posture.label() == "dev"
        || matches!(std::env::var("ENV").as_deref(), Ok("local"))
}
const NAME: &str = "IPE_ENV";
fn unrelated() -> &'static str { "ENVIRONMENT" }
"#;
    assert_eq!(
        posture_reads("fixture", src),
        counted(&[("\"ENV\"", 2), ("\"IPE_ENV\"", 2), (".posture", 1)])
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = posture_reads("fixture", "fn production( { posture_is_production() }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// Every posture read outside `telemetry.rs` is an admitted one, at its
/// admitted count.
#[test]
fn every_posture_read_outside_telemetry_is_admitted() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in [
        POSTURE_OWNER,
        "app_config.rs",
        "web/console.rs",
        "server.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let mut found: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (name, src) in sources.iter().filter(|(name, _)| name != POSTURE_OWNER) {
        for (form, count) in posture_reads(name, src) {
            found.insert((name.clone(), form), count);
        }
    }
    let admitted: BTreeMap<(String, String), usize> = ADMITTED
        .iter()
        .map(|(file, form, count)| (((*file).to_owned(), (*form).to_owned()), *count))
        .collect();
    assert_eq!(
        found, admitted,
        "a posture read outside {POSTURE_OWNER} must be admitted in ADMITTED; a dev-only \
         relaxation opens only under a `DevIntent`/`DevSurface` token"
    );
}

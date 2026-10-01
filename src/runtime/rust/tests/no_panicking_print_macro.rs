//! Print-macro scan: no runtime production code calls a print macro that
//! panics on a failed write.
//!
//! `println!`, `print!`, `eprintln!`, `eprint!`, and `dbg!` panic when the
//! write fails, so a closed downstream pipe (`EPIPE`) would abort the program.
//! Every runtime stdout/stderr line goes through `system::write_stdout_line`
//! or `system::write_stderr_line` (or the tagged `emit_runtime_log*`
//! emitters built on them) instead.
//!
//! Every `.rs` file under `src/`, `system.rs` included, is parsed with `syn`,
//! so the scan reads the syntax tree rustc does: comments and string literals
//! are never code, and a `#[cfg(...)]` proven test-only removes exactly the
//! node it is attached to and nothing after it. A source that does not parse
//! fails the scan. A macro body is scanned token by token with no
//! `#[cfg(test)]` honoured, since the macro decides what its attributes mean;
//! a print-macro name followed by `!` there, or renamed by a `use`, counts as
//! a call.
#![cfg(not(target_arch = "wasm32"))]

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, ForeignItem, Ident, ImplItem, Item, Macro, MetaList,
    Stmt, TraitItem, UseRename, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The std macros that panic on a failed write to stdout or stderr.
const PANICKING_PRINT_MACROS: &[&str] = &["println", "print", "eprintln", "eprint", "dbg"];

fn is_print_macro(id: &Ident) -> bool {
    PANICKING_PRINT_MACROS.contains(&id.unraw().to_string().as_str())
}

/// Every print-macro call the production syntax of one file makes, in source
/// order.
#[derive(Default)]
struct Scan {
    calls: Vec<String>,
}

impl Scan {
    /// Records every print-macro name in `tokens` followed by `!` (a call) or
    /// by `as` (a rename), at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut pending: Option<Ident> = None;
        for tree in tokens {
            let next = match tree {
                TokenTree::Group(group) => {
                    self.scan_tokens(group.stream());
                    None
                }
                TokenTree::Punct(punct) => {
                    if let Some(id) = pending.as_ref()
                        && punct.as_char() == '!'
                    {
                        self.calls.push(format!("{}!", id.unraw()));
                    }
                    None
                }
                TokenTree::Ident(id) => {
                    if let Some(prev) = pending.as_ref()
                        && id == "as"
                    {
                        self.calls.push(format!("use {} as …", prev.unraw()));
                    }
                    is_print_macro(&id).then_some(id)
                }
                TokenTree::Literal(_) => None,
            };
            pending = next;
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

    fn visit_use_rename(&mut self, rename: &'ast UseRename) {
        if is_print_macro(&rename.ident) {
            self.calls
                .push(format!("use {} as {}", rename.ident.unraw(), rename.rename));
        }
        visit::visit_use_rename(self, rename);
    }

    fn visit_meta_list(&mut self, list: &'ast MetaList) {
        self.scan_tokens(list.tokens.clone());
        visit::visit_meta_list(self, list);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if let Some(last) = mac.path.segments.last()
            && is_print_macro(&last.ident)
        {
            self.calls.push(format!("{}!", last.ident.unraw()));
        }
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every print-macro call in the production syntax of `src`; a source that
/// does not parse fails.
fn print_calls(name: &str, src: &str) -> Vec<String> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so it cannot be proven free of print macros: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.calls
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must catch or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_print_macro_in_a_production_fn_is_caught() {
    for call in ["println", "print", "eprintln", "eprint", "dbg"] {
        let src = format!("fn production() {{ {call}!(\"x\"); }}");
        assert_eq!(print_calls("fixture", &src), vec![format!("{call}!")]);
    }
}

#[test]
fn a_path_qualified_print_macro_is_caught() {
    let src = "fn production() { std::println!(\"x\"); ::std::eprintln!(\"y\"); }";
    assert_eq!(print_calls("fixture", src), vec!["println!", "eprintln!"]);
}

#[test]
fn a_cfg_test_module_is_dropped_and_production_after_it_is_scanned() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn t() { println!("test-only"); }
}

fn production() { eprintln!("x"); }
"#;
    assert_eq!(print_calls("fixture", src), vec!["eprintln!"]);
}

#[test]
fn an_out_of_line_cfg_test_module_does_not_hide_the_next_item() {
    let src = "#[cfg(test)]\nmod tests;\n\nfn production() {\n    println!(\"x\");\n}\n";
    assert_eq!(print_calls("fixture", src), vec!["println!"]);
}

#[test]
fn a_one_line_cfg_test_module_does_not_hide_the_next_item() {
    let src = "#[cfg(test)]\nmod t {}\nfn production() { eprint!(\"x\"); }\n";
    assert_eq!(print_calls("fixture", src), vec!["eprint!"]);
}

#[test]
fn cfg_test_impl_and_trait_members_are_dropped_alone() {
    let src = r#"
struct S;
impl S {
    #[cfg(test)]
    fn t() { println!("test-only"); }
    fn production() { print!("x"); }
}
trait T {
    #[cfg(test)]
    fn t() { println!("test-only"); }
    fn production() { dbg!(1); }
}
"#;
    assert_eq!(print_calls("fixture", src), vec!["print!", "dbg!"]);
}

#[test]
fn cfg_test_statements_and_expressions_are_dropped_alone() {
    let src = r#"
fn production() {
    #[cfg(test)]
    println!("test-only");
    #[cfg(test)]
    {
        eprintln!("test-only");
    }
    print!("x");
}
"#;
    assert_eq!(print_calls("fixture", src), vec!["print!"]);
}

#[test]
fn a_cfg_not_proven_test_only_is_scanned() {
    let src = r#"
#[cfg(not(test))]
fn a() { println!("a"); }
#[cfg(any(test, feature = "db"))]
fn b() { println!("b"); }
#[cfg(feature = "test")]
fn c() { println!("c"); }
#[cfg(all(test, feature = "db"))]
fn test_only() { println!("dropped"); }
"#;
    assert_eq!(
        print_calls("fixture", src),
        vec!["println!", "println!", "println!"]
    );
}

#[test]
fn a_print_macro_inside_a_macro_body_is_caught() {
    let src = r#"
macro_rules! say {
    ($($t:tt)*) => { println!($($t)*) };
}
m! {
    #[cfg(test)]
    fn t() { eprintln!("a macro body honours no cfg"); }
}
fn production() { assert!(true, "{}", { dbg!(1) }); }
"#;
    assert_eq!(
        print_calls("fixture", src),
        vec!["println!", "eprintln!", "dbg!"]
    );
}

#[test]
fn renaming_a_print_macro_is_caught() {
    let src = "use std::println as say;\nuse std::{eprintln as warn};\n";
    assert_eq!(
        print_calls("fixture", src),
        vec!["use println as say", "use eprintln as warn"]
    );
}

#[test]
fn strings_and_comments_are_not_code_and_do_not_hide_what_follows() {
    let src = r####"
/// `println!("doc")` is prose.
fn production() {
    // println!("comment");
    /* eprintln!("block comment"); */
    let s = "println!(\"string\")";
    let r = r#"
#[cfg(test)]
mod tests {
"#;
    let _ = (s, r);
}
fn after() { println!("x"); }
"####;
    assert_eq!(print_calls("fixture", src), vec!["println!"]);
}

#[test]
fn the_write_emitters_are_not_print_macros() {
    let src = r#"
fn production() {
    crate::system::write_stdout_line("x");
    crate::system::write_stderr_line("y");
    let _ = writeln!(std::io::stderr().lock(), "z");
    let println = 1;
    let _ = println;
}
"#;
    assert_eq!(print_calls("fixture", src), Vec::<String>::new());
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = print_calls("fixture", "fn production( { println!(\"x\"); }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// Every source file under `src/`, the emitters' own `system.rs` included,
/// calls no panicking print macro outside test-only code.
#[test]
fn no_runtime_source_calls_a_panicking_print_macro() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in [
        "system.rs",
        "core.rs",
        "db.rs",
        "web/mod.rs",
        "web/style_inject.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let violations: Vec<String> = sources
        .iter()
        .flat_map(|(name, src)| {
            print_calls(name, src)
                .into_iter()
                .map(move |call| format!("{name}: {call}"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "a print macro panics on a broken pipe; route the line through \
         `crate::system::write_stdout_line`/`write_stderr_line` (or `emit_runtime_log`):\n{}",
        violations.join("\n")
    );
}

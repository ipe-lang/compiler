//! Startup-fact single-emitter scan.
//!
//! A startup line is written only by the code that performs the fact: the
//! session-store choice by `web/store.rs` (`choose_store` and the one
//! `emit_memory_store_log` call it makes), the bound address by `server.rs`
//! (`bind_app_listener`'s `startup_lines`). A second writer reports a store or
//! listener its caller never chose.
//!
//! Every `.rs` file under `src/` is parsed with `syn`, so comments and doc
//! attributes are never text the program writes, and a `#[cfg(...)]` proven
//! test-only removes exactly the node it is attached to. Every other string
//! literal counts, whichever sink it reaches (`emit_runtime_log*`, a
//! `write_*_line`, a `format!`, a print macro), macro bodies included. A
//! source that does not parse fails the scan.
#![cfg(not(target_arch = "wasm32"))]

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprLit, Field, FieldValue, ImplItem, Item, Lit, Macro, Meta, MetaList,
    Path, Stmt, TraitItem, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// Each startup fact's phrase and the one file whose literals may carry it.
const FACT_OWNERS: &[(&str, &str)] = &[
    ("listening", "server.rs"),
    ("session store:", "web/store.rs"),
];

/// The memory-store line's writer.
const MEMORY_LOG_FN: &str = "emit_memory_store_log";

/// The one file that may name [`MEMORY_LOG_FN`], exactly once.
const MEMORY_LOG_CALLER: &str = "web/store.rs";

/// The production string literals and `emit_memory_store_log` references of
/// one file.
#[derive(Default)]
struct Scan {
    literals: Vec<String>,
    memory_log_refs: usize,
}

impl Scan {
    /// Records every string literal and every `emit_memory_store_log` name in
    /// `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(id) => {
                    if id == MEMORY_LOG_FN {
                        self.memory_log_refs = self.memory_log_refs.saturating_add(1);
                    }
                }
                TokenTree::Literal(lit) => {
                    if let Lit::Str(s) = Lit::new(lit) {
                        self.literals.push(s.value());
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

    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        // A doc comment is documentation, not a line the program writes.
        if matches!(&attr.meta, Meta::NameValue(nv) if nv.path.is_ident("doc")) {
            return;
        }
        visit::visit_attribute(self, attr);
    }

    fn visit_meta_list(&mut self, list: &'ast MetaList) {
        self.scan_tokens(list.tokens.clone());
        visit::visit_meta_list(self, list);
    }

    fn visit_expr_lit(&mut self, lit: &'ast ExprLit) {
        if let Lit::Str(s) = &lit.lit {
            self.literals.push(s.value());
        }
        visit::visit_expr_lit(self, lit);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        if path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == MEMORY_LOG_FN)
        {
            self.memory_log_refs = self.memory_log_refs.saturating_add(1);
        }
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The production literals and `emit_memory_store_log` references of `src`;
/// a source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its startup writers cannot be proven: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut found = Scan::default();
    if let Ok(file) = &parsed {
        found.visit_file(file);
    }
    found
}

/// Every second writer of a startup fact across `sources`, one line each;
/// empty when each fact has its one writer.
fn violations(sources: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut memory_log_refs: Vec<(String, usize)> = Vec::new();
    for (name, src) in sources {
        let file = scan(name, src);
        for literal in &file.literals {
            for (phrase, owner) in FACT_OWNERS {
                if literal.contains(phrase) && name != owner {
                    found.push(format!(
                        "{name}: writes {literal:?}; the {phrase:?} fact is written only by {owner}"
                    ));
                }
            }
        }
        if file.memory_log_refs > 0 {
            memory_log_refs.push((name.clone(), file.memory_log_refs));
        }
    }
    if memory_log_refs != [(MEMORY_LOG_CALLER.to_owned(), 1)] {
        found.push(format!(
            "{MEMORY_LOG_FN} must be named exactly once in production, by \
             {MEMORY_LOG_CALLER}'s choose_store; found {memory_log_refs:?}"
        ));
    }
    found
}

#[test]
fn startup_fact_single_emitter() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&root);
    for owner in FACT_OWNERS.iter().map(|(_, owner)| *owner) {
        assert!(
            sources.iter().any(|(name, _)| name == owner),
            "the fact owner {owner} is not under {}, so the scan would pass on nothing",
            root.display()
        );
    }
    let found = violations(&sources);
    assert!(
        found.is_empty(),
        "a startup fact has a second writer:\n{}",
        found.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Refusals: each planted second writer the scan must catch, and each shape it
// must not count.
// ---------------------------------------------------------------------------

/// The owners' minimal shapes, so a planted file is the only difference.
fn owners() -> Vec<(String, String)> {
    vec![
        (
            "server.rs".to_owned(),
            "fn startup_lines(addr: &str) -> String { format!(\"listening on http://{addr}\") }"
                .to_owned(),
        ),
        (
            "web/store.rs".to_owned(),
            "fn choose_store(t: u64) { emit_memory_store_log(t); }\n\
             fn emit_memory_store_log(t: u64) { let _ = format!(\"session store: memory ({t})\"); }"
                .to_owned(),
        ),
    ]
}

/// The violations of the owners plus `src` planted as `web/mod.rs`.
fn with_planted(src: &str) -> Vec<String> {
    let mut sources = owners();
    sources.push(("web/mod.rs".to_owned(), src.to_owned()));
    violations(&sources)
}

#[test]
fn the_owners_alone_pass() {
    assert_eq!(violations(&owners()), Vec::<String>::new());
}

#[test]
fn a_planted_listening_writer_is_caught_through_every_sink() {
    for src in [
        "fn f(port: u16) { crate::system::emit_runtime_log_stdout(\"web\", &format!(\"listening on :{port}\")); }",
        "fn f() { crate::system::emit_runtime_log(\"web\", \"listening on :8000\"); }",
        "fn f() { crate::system::emit_runtime_log_stamped(\"t\", \"web\", \"listening on :8000\"); }",
        "fn f() { crate::system::write_stdout_line(\"[ipe.web] listening on :8000\"); }",
        "fn f() { eprintln!(\"listening on {}\", 8000); }",
        "const LINE: &str = \"listening on :8000\";",
    ] {
        assert_eq!(with_planted(src).len(), 1, "not caught: {src}");
    }
}

#[test]
fn a_planted_store_writer_is_caught() {
    for src in [
        "fn f() { crate::system::emit_runtime_log(\"live\", \"session store: memory\"); }",
        "fn f(t: u64) { crate::web::store::emit_memory_store_log(t); }",
        "fn f() { let _ = emit_memory_store_log; }",
        "fn f(t: u64) { tokio::spawn(async move { emit_memory_store_log(t) }); }",
        "fn f(t: u64) { m!(emit_memory_store_log(t)); }",
    ] {
        assert_eq!(with_planted(src).len(), 1, "not caught: {src}");
    }
}

#[test]
fn a_second_call_in_the_owner_is_caught() {
    let mut sources = owners();
    if let Some((_, src)) = sources
        .iter_mut()
        .find(|(name, _)| name == MEMORY_LOG_CALLER)
    {
        src.push_str("\nfn console() { emit_memory_store_log(1); }");
    }
    assert_eq!(violations(&sources).len(), 1);
}

#[test]
fn docs_comments_and_test_only_code_are_not_writers() {
    let src = r#"
/// Logs nothing; the listening line and the session store: line live elsewhere.
// listening on :8000
fn production() {}

#[cfg(test)]
mod tests {
    fn t() { let _ = "listening on :8000"; let _ = "session store: memory"; }
}
"#;
    assert_eq!(with_planted(src), Vec::<String>::new());
}

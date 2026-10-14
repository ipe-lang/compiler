//! Ceiling-kind scan: a refusal that names a declared ceiling reaches an Ipê
//! `Error` as `LimitExceeded` (or `Unavailable`), never as `Unexpected` through
//! the `From<String>` bridge.
//!
//! Every `.rs` file under `src/` is parsed with `syn`. A string literal whose
//! text names a ceiling (`exceeds`, `ceiling`, `too many`, `too large`, `too
//! long`, `too deep`, `limit reached`, `size limit`) is a violation when an
//! enclosing call is an unclassified error sink (an `Err(…)` constructor, or
//! `unexpected(…)`/`ipe_error_unexpected(…)`) and no enclosing call is a typed
//! kind constructor (`from_limit_exceeded`, `limit_exceeded`, `unavailable`,
//! `invalid_input`, the other `IpeError` kind constructors, or a
//! `LimitRefusal`). Inside a macro body, an identifier path followed by a
//! parenthesised group counts as a call. Attributes (doc comments, `#[error]`)
//! are not code. A `#[cfg(…)]` proven test-only removes exactly the node it is
//! attached to.
//!
//! The sites that keep a ceiling phrase in an unclassified error are listed in
//! [`ADMITTED`] by file, message prefix, and exact count; an entry that no
//! longer matches its count is drift and fails the scan too.
#![cfg(not(target_arch = "wasm32"))]

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprCall, ExprMethodCall, Field, FieldValue, ImplItem, Item, LitStr,
    Macro, Stmt, TraitItem, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// A site admitted to keep a ceiling phrase in an unclassified error.
struct Admitted {
    /// The source path relative to `src/`.
    file: &'static str,
    /// The start of the message literal.
    prefix: &'static str,
    /// How many literals in `file` start with `prefix` and reach a sink.
    count: usize,
}

/// Each entry is a refusal that is not a declared ceiling, or one that never
/// reaches an Ipê `Error`.
const ADMITTED: &[Admitted] = &[
    // A malformed currency code, not a ceiling.
    Admitted {
        file: "money.rs",
        prefix: "Money.setRate: currency code too long",
        count: 1,
    },
];

/// The words that name a declared ceiling in a refusal message.
const CEILING_PHRASES: &[&str] = &[
    "exceed",
    "ceiling",
    "too large",
    "too many",
    "too long",
    "too deep",
    "limit reached",
    "size limit",
];

/// The `IpeError` constructors that classify a message's kind, matched as the
/// last segment of a call path.
const TYPED_CONSTRUCTORS: &[&str] = &[
    "io",
    "network",
    "ffi",
    "decode",
    "invalid_input",
    "conflict",
    "unavailable",
    "limit_exceeded",
    "from_limit_exceeded",
    "from_unavailable",
    "timeout",
    "not_found",
    "permission_denied",
];

/// The keywords that can precede a parenthesised group without calling it.
const KEYWORDS: &[&str] = &[
    "return", "if", "match", "in", "while", "let", "for", "loop", "else", "move", "as", "mut",
    "ref", "fn", "where", "break", "continue", "async", "await", "unsafe", "impl", "dyn", "box",
    "yield", "const", "static", "type", "use", "mod", "pub", "struct", "enum", "trait",
];

fn names_ceiling(text: &str) -> bool {
    let lower = text.to_lowercase();
    CEILING_PHRASES.iter().any(|phrase| lower.contains(phrase))
}

fn is_typed(path: &[String]) -> bool {
    if path.iter().any(|segment| segment == "LimitRefusal") {
        return true;
    }
    path.last().is_some_and(|last| {
        TYPED_CONSTRUCTORS.contains(&last.as_str())
            || (last.starts_with("ipe_error_") && last != "ipe_error_unexpected")
    })
}

fn is_sink(path: &[String]) -> bool {
    path.iter().any(|segment| segment == "Err")
        || path
            .last()
            .is_some_and(|last| last == "unexpected" || last == "ipe_error_unexpected")
}

/// Every ceiling-phrase literal that reaches an unclassified error sink in the
/// production syntax of one file, in source order.
#[derive(Default)]
struct Scan {
    /// The call paths enclosing the node being visited, innermost last.
    calls: Vec<Vec<String>>,
    hits: Vec<String>,
}

impl Scan {
    fn record(&mut self, text: String) {
        if names_ceiling(&text)
            && !self.calls.iter().any(|path| is_typed(path))
            && self.calls.iter().any(|path| is_sink(path))
        {
            self.hits.push(text);
        }
    }

    /// Scans a macro body: a string literal is recorded under the calls
    /// enclosing it, and an identifier path followed by a parenthesised group
    /// calls that group.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => {
                    let path = if group.delimiter() == Delimiter::Parenthesis {
                        token_path_before(&trees, at)
                    } else {
                        Vec::new()
                    };
                    self.calls.push(path);
                    self.scan_tokens(group.stream());
                    self.calls.pop();
                }
                TokenTree::Literal(literal) => {
                    let parsed = syn::parse2::<LitStr>(TokenStream::from(TokenTree::Literal(
                        literal.clone(),
                    )));
                    if let Ok(lit) = parsed {
                        self.record(lit.value());
                    }
                }
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }
}

/// The identifier path (`a::b::c`) that ends right before `trees[at]`, or an
/// empty path when a keyword or anything other than an identifier precedes it.
fn token_path_before(trees: &[TokenTree], at: usize) -> Vec<String> {
    let mut path = Vec::new();
    let Some(mut end) = at.checked_sub(1) else {
        return path;
    };
    let Some(TokenTree::Ident(last)) = trees.get(end) else {
        return path;
    };
    let last = last.unraw().to_string();
    if KEYWORDS.contains(&last.as_str()) {
        return path;
    }
    path.push(last);
    loop {
        let colons = end.checked_sub(2).and_then(|first| trees.get(first..end));
        let ident = end.checked_sub(3).and_then(|i| trees.get(i));
        match (colons, ident) {
            (Some([TokenTree::Punct(a), TokenTree::Punct(b)]), Some(TokenTree::Ident(id)))
                if a.as_char() == ':' && b.as_char() == ':' =>
            {
                path.insert(0, id.unraw().to_string());
                end = end.saturating_sub(3);
            }
            _ => break,
        }
    }
    path
}

/// The trailing segments of `expr`'s path that carry no generic arguments, or
/// an empty path when `expr` is not a path.
fn expr_path(expr: &Expr) -> Vec<String> {
    let Expr::Path(path) = expr else {
        return Vec::new();
    };
    let first = path.qself.as_ref().map_or(0, |qself| qself.position);
    let mut names: Vec<String> = path
        .path
        .segments
        .iter()
        .skip(first)
        .rev()
        .take_while(|segment| segment.arguments.is_none())
        .map(|segment| segment.ident.unraw().to_string())
        .collect();
    names.reverse();
    names
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_attribute(&mut self, _attr: &'ast Attribute) {}

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

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        self.visit_expr(&call.func);
        self.calls.push(expr_path(&call.func));
        for arg in &call.args {
            self.visit_expr(arg);
        }
        self.calls.pop();
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.visit_expr(&call.receiver);
        let path = if call.turbofish.is_none() {
            vec![call.method.unraw().to_string()]
        } else {
            Vec::new()
        };
        self.calls.push(path);
        for arg in &call.args {
            self.visit_expr(arg);
        }
        self.calls.pop();
    }

    fn visit_lit_str(&mut self, lit: &'ast LitStr) {
        self.record(lit.value());
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every ceiling-phrase literal of `src` that reaches an unclassified error
/// sink; a source that does not parse fails.
fn unclassified_ceilings(name: &str, src: &str) -> Vec<String> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its ceiling refusals cannot be classified: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.hits
}

/// The violations of `sources` against `admitted`: every unadmitted hit, and
/// every admitted entry whose count no longer matches.
fn violations(sources: &[(String, String)], admitted: &[Admitted]) -> Vec<String> {
    let mut out = Vec::new();
    let mut matched = vec![0usize; admitted.len()];
    for (name, src) in sources {
        for hit in unclassified_ceilings(name, src) {
            let entry = admitted
                .iter()
                .position(|a| a.file == name && hit.starts_with(a.prefix));
            match entry.and_then(|i| matched.get_mut(i)) {
                Some(seen) => *seen = seen.saturating_add(1),
                None => out.push(format!("{name}: {hit:?}")),
            }
        }
    }
    for (entry, seen) in admitted.iter().zip(&matched) {
        if *seen != entry.count {
            out.push(format!(
                "{}: admitted {:?} expects {} site(s), found {seen}",
                entry.file, entry.prefix, entry.count
            ));
        }
    }
    out
}

fn fixture(src: &str) -> Vec<String> {
    unclassified_ceilings("fixture", src)
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must catch or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_ceiling_message_through_each_unclassified_sink_is_caught() {
    let src = r#"
fn a() -> Result<(), String> { Err(format!("input exceeds {} bytes", 1)) }
fn b() -> IpeResult<()> { IpeResult::Err("too many rows".to_string().into()) }
fn c() -> IpeError { IpeError::unexpected("limit reached".to_owned()) }
fn d() -> IpeError { ipe_error_unexpected(String::from("over the size limit")) }
fn e() -> Result<(), E> { return Err(E::from(format!("the ceiling of {}", 3))); }
"#;
    assert_eq!(
        fixture(src),
        vec![
            "input exceeds {} bytes",
            "too many rows",
            "limit reached",
            "over the size limit",
            "the ceiling of {}",
        ]
    );
}

#[test]
fn a_ceiling_message_inside_a_macro_body_is_caught() {
    let src = r#"
m! {
    #[cfg(test)]
    fn t() -> Result<(), String> { Err("too large".into()) }
}
fn production() { run!(|| IpeResult::Err(format!("too deep").into())); }
"#;
    assert_eq!(fixture(src), vec!["too large", "too deep"]);
}

#[test]
fn a_typed_kind_constructor_classifies_the_message() {
    let src = r#"
fn a() -> Result<(), E> { Err(E::from_limit_exceeded(format!("exceeds {}", 1))) }
fn b() -> IpeResult<()> { IpeResult::Err(IpeError::limit_exceeded("too many")) }
fn c() -> Result<(), LimitRefusal> { Err(LimitRefusal::new("the ceiling".to_owned())) }
fn d() -> IpeResult<()> { IpeResult::Err(IpeError::invalid_input("too long".to_owned())) }
fn e() -> IpeResult<()> { IpeResult::Err(IpeError::unavailable("ceiling reached".to_owned())) }
fn f() -> IpeError { ipe_error_limit_exceeded("too large".to_owned()) }
"#;
    assert_eq!(fixture(src), Vec::<String>::new());
}

#[test]
fn a_ceiling_message_outside_an_error_sink_is_not_a_refusal() {
    let src = r#"
/// The read exceeds the ceiling.
#[error("too many waiters")]
struct S;
fn log() { emit_runtime_log("the queue is too large"); }
fn display() -> String { format!("exceeds {}", 1) }
"#;
    assert_eq!(fixture(src), Vec::<String>::new());
}

#[test]
fn test_only_code_is_dropped_and_production_after_it_is_scanned() {
    let src = r#"
#[cfg(test)]
mod tests {
    fn t() -> Result<(), String> { Err("too many".into()) }
}
#[cfg(not(test))]
fn production() -> Result<(), String> { Err("too long".into()) }
"#;
    assert_eq!(fixture(src), vec!["too long"]);
}

#[test]
fn an_admitted_entry_must_match_its_exact_count() {
    let sources = vec![(
        "x.rs".to_owned(),
        r#"fn a() -> Result<(), String> { Err("x: too many".into()) }"#.to_owned(),
    )];
    let exact = [Admitted {
        file: "x.rs",
        prefix: "x: ",
        count: 1,
    }];
    assert_eq!(violations(&sources, &exact), Vec::<String>::new());
    let stale = [Admitted {
        file: "x.rs",
        prefix: "x: ",
        count: 2,
    }];
    assert_eq!(
        violations(&sources, &stale),
        vec!["x.rs: admitted \"x: \" expects 2 site(s), found 1"]
    );
    let other_file = [Admitted {
        file: "y.rs",
        prefix: "x: ",
        count: 1,
    }];
    assert_eq!(
        violations(&sources, &other_file),
        vec![
            "x.rs: \"x: too many\"",
            "y.rs: admitted \"x: \" expects 1 site(s), found 0",
        ]
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = fixture("fn production( { Err(\"too many\") }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

#[test]
fn no_runtime_ceiling_refusal_reaches_unexpected() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in [
        "file.rs",
        "http_client.rs",
        "system.rs",
        "js_port.rs",
        "db.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let found = violations(&sources, ADMITTED);
    assert!(
        found.is_empty(),
        "a refusal naming a declared ceiling must reach `IpeError` as `LimitExceeded` \
         (`FromLimitExceeded::from_limit_exceeded`, `IpeError::limit_exceeded`) or, when \
         it frees by itself, `Unavailable`; never `Unexpected` through `From<String>`:\n{}",
        found.join("\n")
    );
}

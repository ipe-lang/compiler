//! Worker scan: every worker script body makes only admitted calls.
//!
//! `src/web/worker.rs` is parsed with `syn`. Every string constant there must
//! be listed in `WORKER_CONSTANTS`, and the file holds no other literal, no
//! macro, no `use`, no method call and no path reaching outside the file, so
//! no body can be built where the scan cannot read it. Each listed
//! body is then read by a JavaScript tokenizer that admits a closed vocabulary:
//! a call is admitted only when its whole member chain is in [`ADMITTED_CALLS`],
//! every identifier must be in [`VOCABULARY`], `addEventListener` takes only an
//! event in [`ADMITTED_EVENTS`], and a computed member, a template, a comment,
//! an escape, a call on a call's result or any character outside the admitted
//! set fails the scan. The scan lists what is admitted, never the banned
//! spellings, so a spelling no list foresaw is refused.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprArray, ExprMethodCall, ExprPath, ExprReference, Item, ItemConst, ItemUse,
    Lit, LitStr, Macro,
};

/// The `worker.rs` source the scan reads.
const WORKER_SOURCE: &str = include_str!("../src/web/worker.rs");

/// The constant listing every worker body.
const LISTING: &str = "WORKER_CONSTANTS";

/// Every member chain a worker body may call.
const ADMITTED_CALLS: &[&str] = &[
    "self.addEventListener",
    "self.skipWaiting",
    "self.registration.unregister",
    "self.registration.navigationPreload.enable",
    "event.waitUntil",
    "event.respondWith",
    "new Response",
    "self.registration.showNotification",
    "clients.matchAll",
    "clients.openWindow",
    "client.focus",
    "client.postMessage",
];

/// Every event a worker body may listen for.
const ADMITTED_EVENTS: &[&str] = &["install", "activate", "fetch", "push", "notificationclick"];

/// Every identifier a worker body may spell.
const VOCABULARY: &[&str] = &[
    "self",
    "addEventListener",
    "skipWaiting",
    "registration",
    "unregister",
    "navigationPreload",
    "enable",
    "event",
    "waitUntil",
    "respondWith",
    "preloadResponse",
    "Response",
    "showNotification",
    "clients",
    "matchAll",
    "openWindow",
    "client",
    "focus",
    "postMessage",
    "function",
    "return",
    "if",
    "else",
    "new",
    "typeof",
    "undefined",
    "null",
    "true",
    "false",
];

/// The keywords that precede `(` without being a call.
const NON_CALL_KEYWORDS: &[&str] = &["function", "if", "return", "typeof"];

/// The punctuation a worker body may hold outside a string.
const PUNCTUATION: &[char] = &[
    '(', ')', '{', '}', ';', ',', '.', '=', '!', '&', '|', '?', ':', '<', '>',
];

/// One finding of the JavaScript scan.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    /// A call whose member chain is not admitted.
    Call(String),
    /// An identifier outside the vocabulary.
    Identifier(String),
    /// An `addEventListener` whose first argument is not an admitted event.
    EventName,
    /// A computed member access, `[` or `]`.
    Bracket,
    /// A template literal.
    Template,
    /// A comment.
    Comment,
    /// A string literal with no closing quote.
    UnclosedString,
    /// A character outside the admitted set, an escape included.
    Character(char),
}

/// One token of a worker body.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Number,
    Punct(char),
}

/// The body's tokens, and every finding the tokenizer itself reports.
fn tokenize(body: &str) -> (Vec<Token>, Vec<Finding>) {
    let mut tokens = Vec::new();
    let mut findings = Vec::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\n' | '\t' => {}
            '\'' | '"' => {
                let mut text = String::new();
                let mut closed = false;
                for inner in chars.by_ref() {
                    if inner == c {
                        closed = true;
                        break;
                    }
                    if inner == '\\' || !(inner == ' ' || inner.is_ascii_graphic()) {
                        findings.push(Finding::Character(inner));
                    }
                    text.push(inner);
                }
                if !closed {
                    findings.push(Finding::UnclosedString);
                }
                tokens.push(Token::Str(text));
            }
            '`' => findings.push(Finding::Template),
            '[' | ']' => findings.push(Finding::Bracket),
            '/' if matches!(chars.peek(), Some('/' | '*')) => {
                findings.push(Finding::Comment);
                break;
            }
            c if c.is_ascii_alphabetic() || c == '_' || c == '$' => {
                let mut name = String::from(c);
                while let Some(next) =
                    chars.next_if(|n| n.is_ascii_alphanumeric() || *n == '_' || *n == '$')
                {
                    name.push(next);
                }
                tokens.push(Token::Ident(name));
            }
            c if c.is_ascii_digit() => {
                while chars.next_if(char::is_ascii_digit).is_some() {}
                tokens.push(Token::Number);
            }
            c if PUNCTUATION.contains(&c) => tokens.push(Token::Punct(c)),
            other => findings.push(Finding::Character(other)),
        }
    }
    (tokens, findings)
}

/// Every finding in one worker body.
fn scan(body: &str) -> Vec<Finding> {
    let (tokens, mut findings) = tokenize(body);
    for token in &tokens {
        if let Token::Ident(name) = token
            && !VOCABULARY.contains(&name.as_str())
        {
            findings.push(Finding::Identifier(name.clone()));
        }
    }
    let mut at = 0;
    while let Some(token) = tokens.get(at) {
        let previous = at.checked_sub(1).and_then(|before| tokens.get(before));
        match token {
            Token::Ident(_) if previous != Some(&Token::Punct('.')) => {
                let (chain, end) = member_chain(&tokens, at);
                if tokens.get(end) == Some(&Token::Punct('(')) {
                    judge_call(&tokens, previous, chain, end, &mut findings);
                }
                at = end;
            }
            Token::Punct('.') if !matches!(previous, Some(Token::Ident(_))) => {
                let (chain, end) = member_chain(&tokens, at + 1);
                findings.push(Finding::Call(format!("<result>.{chain}")));
                at = end;
            }
            Token::Punct('(') if matches!(previous, Some(Token::Punct(')'))) => {
                findings.push(Finding::Call("<result>".to_owned()));
                at += 1;
            }
            _ => at += 1,
        }
    }
    findings
}

/// The dotted member chain starting at `start`, and the index after it.
fn member_chain(tokens: &[Token], start: usize) -> (String, usize) {
    let mut parts = Vec::new();
    let mut at = start;
    while let Some(Token::Ident(name)) = tokens.get(at) {
        parts.push(name.as_str());
        if tokens.get(at + 1) == Some(&Token::Punct('.')) {
            at += 2;
        } else {
            at += 1;
            break;
        }
    }
    (parts.join("."), at)
}

/// Judge the call of `chain`, whose `(` sits at `open`.
fn judge_call(
    tokens: &[Token],
    previous: Option<&Token>,
    chain: String,
    open: usize,
    findings: &mut Vec<Finding>,
) {
    if NON_CALL_KEYWORDS.contains(&chain.as_str()) {
        return;
    }
    let called = if matches!(previous, Some(Token::Ident(word)) if word == "new") {
        format!("new {chain}")
    } else {
        chain
    };
    if !ADMITTED_CALLS.contains(&called.as_str()) {
        findings.push(Finding::Call(called));
        return;
    }
    if called == "self.addEventListener" {
        let admitted = matches!(
            tokens.get(open + 1),
            Some(Token::Str(name)) if ADMITTED_EVENTS.contains(&name.as_str())
        );
        if !admitted {
            findings.push(Finding::EventName);
        }
    }
}

/// What `worker.rs` holds: its string constants, the listing, and every
/// string literal or macro outside a constant.
#[derive(Default)]
struct WorkerFile {
    constants: BTreeMap<String, String>,
    listed: Option<Vec<String>>,
    strays: Vec<String>,
}

impl<'ast> Visit<'ast> for WorkerFile {
    fn visit_attribute(&mut self, _attr: &'ast Attribute) {}

    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        let name = item.ident.to_string();
        match &*item.expr {
            Expr::Lit(lit) => match &lit.lit {
                Lit::Str(text) => {
                    self.constants.insert(name, text.value());
                }
                _ => visit::visit_item_const(self, item),
            },
            Expr::Reference(ExprReference { expr, .. }) if name == LISTING => {
                if let Expr::Array(ExprArray { elems, .. }) = &**expr {
                    let names = elems.iter().map(|elem| match elem {
                        Expr::Path(path) => path
                            .path
                            .get_ident()
                            .map_or_else(|| "<path>".to_owned(), ToString::to_string),
                        _ => "<expr>".to_owned(),
                    });
                    self.listed = Some(names.collect());
                } else {
                    self.strays.push(format!("{LISTING} is not an array"));
                }
            }
            _ => visit::visit_item_const(self, item),
        }
    }

    fn visit_lit_str(&mut self, lit: &'ast LitStr) {
        self.strays
            .push(format!("string literal {:?}", lit.value()));
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.strays
            .push(format!("macro {:?}", mac.path.get_ident()));
    }

    fn visit_lit(&mut self, lit: &'ast Lit) {
        match lit {
            Lit::Str(text) => self.visit_lit_str(text),
            _ => self
                .strays
                .push("a literal that is not a string".to_owned()),
        }
    }

    fn visit_item_use(&mut self, _item: &'ast ItemUse) {
        self.strays.push("a use item".to_owned());
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        let segments: Vec<String> = expr
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let local = expr.qself.is_none()
            && expr.path.leading_colon.is_none()
            && match segments.as_slice() {
                [_] => true,
                [first, _] => first == "Self",
                _ => false,
            };
        if !local {
            self.strays.push(format!("path {}", segments.join("::")));
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.strays.push(format!("method call {}", call.method));
        visit::visit_expr_method_call(self, call);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        if let Item::Static(item) = item {
            self.strays.push(format!("static {}", item.ident));
        }
        visit::visit_item(self, item);
    }
}

/// The parsed `worker.rs`.
#[allow(clippy::expect_used)] // test: `worker.rs` is compiled source and parses
fn worker_file() -> WorkerFile {
    let file = syn::parse_file(WORKER_SOURCE).expect("worker.rs parses");
    let mut found = WorkerFile::default();
    found.visit_file(&file);
    found
}

#[test]
fn every_worker_body_is_a_listed_literal_constant() {
    let file = worker_file();
    assert!(
        file.strays.is_empty(),
        "outside a listed constant: {:?}",
        file.strays
    );
    assert!(
        file.listed.is_some(),
        "{LISTING} is an array of constant names"
    );
    let listed = file.listed.unwrap_or_default();
    assert!(!listed.is_empty(), "{LISTING} lists no body");
    let constants: Vec<&String> = file.constants.keys().collect();
    let mut sorted = listed.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        listed.len(),
        "{LISTING} repeats a body: {listed:?}"
    );
    assert_eq!(
        sorted.iter().collect::<Vec<_>>(),
        constants,
        "every string constant in worker.rs is listed in {LISTING}, and only those"
    );
}

#[test]
fn every_worker_body_makes_only_admitted_calls() {
    let file = worker_file();
    assert!(!file.constants.is_empty(), "no worker body read");
    for (name, body) in &file.constants {
        assert_eq!(scan(body), Vec::new(), "{name}");
    }
}

/// The retire body read from `worker.rs`, the base of every planted copy.
fn retire_body() -> String {
    worker_file()
        .constants
        .remove("RETIRE_BODY")
        .unwrap_or_default()
}

#[test]
fn a_planted_body_outside_the_admitted_calls_fails_the_scan() {
    let base = retire_body();
    assert!(!base.is_empty(), "RETIRE_BODY is read from worker.rs");
    let call = |name: &str| Finding::Call(name.to_owned());
    let ident = |name: &str| Finding::Identifier(name.to_owned());
    let planted: &[(&str, Finding)] = &[
        ("fetch('/x');", call("fetch")),
        ("caches.open('v1');", call("caches.open")),
        ("importScripts('/x.js');", call("importScripts")),
        ("self[\"fe\"+\"tch\"]('/x');", Finding::Bracket),
        (
            "self.registration.update();",
            call("self.registration.update"),
        ),
        (
            "self.skipWaiting().then(function(){});",
            call("<result>.then"),
        ),
        ("(function(){})();", call("<result>")),
        (
            "self.addEventListener('message',function(){});",
            Finding::EventName,
        ),
        (
            "self.addEventListener(name,function(){});",
            Finding::EventName,
        ),
        ("self.onfetch=function(){};", ident("onfetch")),
        ("var f=self.skipWaiting;f();", ident("var")),
        ("new Request('/x');", call("new Request")),
        ("// note", Finding::Comment),
        ("/* note */", Finding::Comment),
        ("`x`;", Finding::Template),
        ("\\u0066etch('/x');", Finding::Character('\\')),
        (
            "self.addEventListener('fe\\u0074ch',function(){});",
            Finding::Character('\\'),
        ),
        ("self.x='open", Finding::UnclosedString),
        ("self.x=1+1;", Finding::Character('+')),
    ];
    for (suffix, expected) in planted {
        let findings = scan(&format!("{base}{suffix}"));
        assert!(
            findings.contains(expected),
            "{suffix:?} yields {expected:?}, got {findings:?}"
        );
    }
}

#[test]
fn a_planted_unlisted_constant_or_macro_fails_the_listing() {
    let planted =
        format!("{WORKER_SOURCE}\npub const EXTRA_BODY: &str = \"self.skipWaiting();\";\n");
    let file = {
        let mut found = WorkerFile::default();
        if let Ok(parsed) = syn::parse_file(&planted) {
            found.visit_file(&parsed);
        }
        found
    };
    assert!(file.constants.contains_key("EXTRA_BODY"));
    assert!(
        !file
            .listed
            .unwrap_or_default()
            .contains(&"EXTRA_BODY".to_owned()),
        "the planted body is unlisted, so the listing check sees it"
    );
    let with_macro =
        format!("{WORKER_SOURCE}\npub const MACRO_BODY: &str = concat!(\"a\", \"b\");\n");
    let mut found = WorkerFile::default();
    if let Ok(parsed) = syn::parse_file(&with_macro) {
        found.visit_file(&parsed);
    }
    assert!(
        found.strays.iter().any(|stray| stray.starts_with("macro")),
        "a body built by a macro is a stray: {:?}",
        found.strays
    );
}

/// The strays a planted copy of `worker.rs` with `suffix` appended holds.
fn planted_strays(suffix: &str) -> Vec<String> {
    let mut found = WorkerFile::default();
    if let Ok(parsed) = syn::parse_file(&format!("{WORKER_SOURCE}\n{suffix}\n")) {
        found.visit_file(&parsed);
    } else {
        found
            .strays
            .push("the planted copy does not parse".to_owned());
    }
    found.strays
}

#[test]
fn a_body_built_outside_a_string_constant_fails_the_listing() {
    assert_eq!(
        planted_strays(""),
        Vec::<String>::new(),
        "the real file is clean"
    );
    let planted: &[(&str, &str)] = &[
        (
            "pub const BYTES: &[u8] = b\"fetch('/x');\";",
            "a literal that is not a string",
        ),
        (
            "pub const CODES: [u8; 1] = [102];",
            "a literal that is not a string",
        ),
        (
            "pub const CHARS: [char; 1] = ['f'];",
            "a literal that is not a string",
        ),
        ("use crate::web::OTHER_BODY;", "a use item"),
        (
            "pub const FOREIGN: &str = crate::web::OTHER_BODY;",
            "path crate::web::OTHER_BODY",
        ),
        (
            "pub const FOREIGN: &str = ::core::primitive::str::trim(RETIRE_BODY);",
            "path core::primitive::str::trim",
        ),
        (
            "pub fn body() -> &'static str { RETIRE_BODY.trim_start() }",
            "method call trim_start",
        ),
    ];
    for (suffix, expected) in planted {
        let strays = planted_strays(suffix);
        assert!(
            strays.iter().any(|stray| stray == expected),
            "{suffix:?} yields {expected:?}, got {strays:?}"
        );
    }
}

//! Serde error text scan: a `serde_json::Error` becomes text only in `json.rs`.
//!
//! A `serde_json` data error quotes the input value it refused, so its
//! `Display` or `Debug` text can carry a secret into a log line or a returned
//! error. The one renderer is `json::json_failure_text` (and `json_failure`,
//! built on it). Every `.rs` file under `src/` except `json.rs` is parsed with
//! `syn`, and four kinds of site are counted in its production syntax, keyed by
//! the function they are written in:
//!
//! - **`Rendered`.** A failure binding is read for anything other than its
//!   kind. A failure binding is the binder of an `Err(..)` pattern over a
//!   `serde_json` outcome (`match`, `if let`, `let`, a tuple scrutinee), the
//!   parameter of a closure handed the error (`map_err`, `unwrap_or_else`,
//!   `or_else`, `inspect_err`, `is_err_and`, `map_or_else`), or a parameter
//!   typed `serde_json::Error`. Reading it through an inspector (`classify`,
//!   `is_eof`, `line`, …), or passing it to the renderer or to a function whose
//!   own parameter is a `serde_json::Error` (scanned in its turn), is not a
//!   site; any other use is, a `{name}` placeholder in a macro's format string
//!   included.
//! - **`Forwarded`.** An unopened outcome leaves the scan's sight: `?`, a call
//!   or macro argument, a `return`, a struct field, a non-closure error
//!   handler, `.err()`/`.unwrap()`/`.expect()`, or a fallible `serde_json`
//!   function taken as a value.
//! - **`Carrier`.** A path ending in `serde_json::Error` or `serde_json::Result`
//!   outside a renderer parameter: a field, a return type, a `From` impl.
//! - **`Import`.** A `use` or `extern crate` that hides the `serde_json` prefix
//!   the scan keys on: a crate rename, a glob, or a fallible function, stream
//!   type, error type or error module imported by name.
//!
//! An outcome is the value of a fallible `serde_json` function, or of a call
//! or method that takes a `serde_json` stream (`Deserializer`, `Serializer`),
//! carried through `let` bindings and adaptors that keep the error (`map`,
//! `and_then`). [`ADMITTED_SITES`] lists each `(file, fn, kind)` with its exact
//! count and reason; an unlisted site and a stale entry both go red.
//! Attributes (doc comments) are not code. A `#[cfg(…)]` proven test-only
//! removes exactly the node it is attached to.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLet, ExprLit,
    ExprMatch, ExprMethodCall, ExprPath, ExprReturn, ExprTry, ExprWhile, Field, FieldValue, FnArg,
    ImplItem, ImplItemFn, Item, ItemExternCrate, ItemFn, ItemUse, Lit, LitStr, Local, Macro, Pat,
    Path, Signature, Stmt, Token, TraitItem, TraitItemFn, Type, UseTree, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// What a counted site does with a `serde_json` failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum SiteKind {
    /// A failure binding read for more than its kind.
    Rendered,
    /// An unopened outcome handed out of the scan's sight.
    Forwarded,
    /// A type path naming `serde_json::Error` or `serde_json::Result`.
    Carrier,
    /// An import that hides the `serde_json` prefix.
    Import,
}

/// A production site admitted on purpose.
struct Admitted {
    /// The source path relative to `src/`.
    file: &'static str,
    /// The function the site is written in, or `<item>` outside any function.
    function: &'static str,
    kind: SiteKind,
    /// How many sites of `kind` occur in `function`.
    count: usize,
    /// Why the failure text cannot carry input into a log or an error.
    reason: &'static str,
}

/// Every production site outside `json.rs`, with its reason.
const ADMITTED_SITES: &[Admitted] = &[
    Admitted {
        file: "debugger/mod.rs",
        function: "export_msgs",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own message log: an encode error names a Rust \
                 type or a non-string map key, never decoded input",
    },
    Admitted {
        file: "js_port.rs",
        function: "js_close_session",
        kind: SiteKind::Rendered,
        count: 2,
        reason: "serialising the program's own close command (native and wasm): an encode \
                 error carries no received input",
    },
    Admitted {
        file: "js_port.rs",
        function: "js_open_session",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own open command: an encode error carries no \
                 received input",
    },
    Admitted {
        file: "js_port.rs",
        function: "js_request",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own request payload: an encode error carries no \
                 received input",
    },
    Admitted {
        file: "js_port.rs",
        function: "js_send",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own payload: an encode error carries no received \
                 input",
    },
    Admitted {
        file: "js_port.rs",
        function: "js_send_to_session",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own session command: an encode error carries no \
                 received input",
    },
    Admitted {
        file: "js_port.rs",
        function: "open_session_with_mint",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own open command: an encode error carries no \
                 received input",
    },
    Admitted {
        file: "js_port.rs",
        function: "request_with_mint",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "serialising the program's own request payload: an encode error carries no \
                 received input",
    },
    Admitted {
        file: "jwt.rs",
        function: "jwt_decode_hs256",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "re-encoding claims already decoded to a `Value`: encoding a `Value` has no \
                 data error to quote",
    },
    Admitted {
        file: "jwt.rs",
        function: "jwt_decode_rs256",
        kind: SiteKind::Rendered,
        count: 1,
        reason: "re-encoding claims already decoded to a `Value`: encoding a `Value` has no \
                 data error to quote",
    },
    Admitted {
        file: "web/hub.rs",
        function: "decode_one",
        kind: SiteKind::Rendered,
        count: 2,
        reason: "transitional: a hub row decode echoes the serde error into the runtime log \
                 and the returned error; routing it through `json_failure_text` removes \
                 this entry",
    },
    Admitted {
        file: "web/hub.rs",
        function: "decode_rows",
        kind: SiteKind::Rendered,
        count: 2,
        reason: "transitional: a hub rows decode echoes the serde error into the runtime log \
                 and the returned error; routing it through `json_failure_text` removes \
                 this entry",
    },
    Admitted {
        file: "web/store.rs",
        function: OUTSIDE_FN,
        kind: SiteKind::Carrier,
        count: 1,
        reason: "`PersistError::Encode` holds the session map's encode error; its `Display` \
                 names only the step",
    },
    Admitted {
        file: "web/store.rs",
        function: "write_map",
        kind: SiteKind::Forwarded,
        count: 1,
        reason: "the session map's encode error moves into `PersistError::Encode`, whose \
                 `Display` names only the step",
    },
];

/// The function name recorded for a site outside any function.
const OUTSIDE_FN: &str = "<item>";

/// The one file that renders a `serde_json::Error`, relative to `src/`.
const RENDERER: &str = "json.rs";

/// The renderer's functions; a failure passed to one is not a site.
const RENDERER_FNS: &[&str] = &["json_failure", "json_failure_text"];

const SERDE_JSON: &str = "serde_json";

/// The `serde_json` functions whose value is an outcome.
const FALLIBLE: &[&str] = &[
    "from_str",
    "from_slice",
    "from_value",
    "from_reader",
    "to_string",
    "to_string_pretty",
    "to_vec",
    "to_vec_pretty",
    "to_value",
    "to_writer",
    "to_writer_pretty",
];

/// The `serde_json` stream types; a call or method taking one is an outcome.
const STREAMS: &[&str] = &["Deserializer", "Serializer", "StreamDeserializer"];

/// The methods that read a failure's kind and position, never its text.
const INSPECTORS: &[&str] = &[
    "classify",
    "is_io",
    "is_syntax",
    "is_data",
    "is_eof",
    "line",
    "column",
    "io_error_kind",
];

/// The outcome methods that drop the error.
const DISCARDING: &[&str] = &[
    "ok",
    "unwrap_or",
    "unwrap_or_default",
    "is_ok",
    "is_err",
    "is_ok_and",
    "map_or",
];

/// The outcome methods whose first argument is handed the error.
const ERROR_HANDLERS: &[&str] = &[
    "map_err",
    "unwrap_or_else",
    "or_else",
    "inspect_err",
    "is_err_and",
    "map_or_else",
];

/// The outcome methods that hand the error out unopened.
const UNOPENED: &[&str] = &["err", "unwrap", "expect", "unwrap_err", "expect_err"];

/// The `serde_json` names an import may not bring in under another prefix.
const HIDDEN_ONLY: &[&str] = &[
    "Error",
    "Result",
    "error",
    "de",
    "ser",
    "value",
    "Deserializer",
    "Serializer",
    "StreamDeserializer",
];

fn listed(names: &[&str], name: &str) -> bool {
    names.contains(&name)
}

fn hidden(name: &str) -> bool {
    listed(FALLIBLE, name) || listed(HIDDEN_ONLY, name)
}

fn idents(path: &Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|segment| segment.ident.unraw().to_string())
        .collect()
}

/// The segments of `path` when it starts at `serde_json`.
fn serde_names(path: &Path) -> Option<Vec<String>> {
    let names = idents(path);
    (names.first().map(String::as_str) == Some(SERDE_JSON)).then_some(names)
}

fn last_name(path: &Path) -> Option<String> {
    path.segments
        .last()
        .map(|segment| segment.ident.unraw().to_string())
}

/// A `serde_json::Error` or `serde_json::Result` path.
fn is_carrier_path(path: &Path) -> bool {
    serde_names(path).is_some_and(|names| {
        names
            .last()
            .is_some_and(|last| last == "Error" || last == "Result")
    })
}

/// A parameter type that is a `serde_json::Error`, by value or reference.
fn is_failure_type(ty: &Type) -> bool {
    match ty {
        Type::Reference(reference) => is_failure_type(&reference.elem),
        Type::Paren(paren) => is_failure_type(&paren.elem),
        Type::Group(group) => is_failure_type(&group.elem),
        Type::Path(path) => {
            path.qself.is_none()
                && serde_names(&path.path)
                    .is_some_and(|names| names.last().is_some_and(|last| last == "Error"))
        }
        _ => false,
    }
}

/// The bound name of a plain `let` pattern, through a type ascription.
fn plain_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(ident) if ident.subpat.is_none() => Some(ident.ident.unraw().to_string()),
        Pat::Type(typed) => plain_ident(&typed.pat),
        _ => None,
    }
}

/// What a name or expression holds, as far as the scan tracks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Binding {
    Clean,
    /// A `Result` whose error is a `serde_json::Error`.
    Outcome,
    /// A `serde_json` stream.
    Stream,
    /// A `serde_json::Error`.
    Failure,
}

/// The names of every function with a `serde_json::Error` parameter.
#[derive(Default)]
struct Handlers {
    names: BTreeSet<String>,
}

impl Handlers {
    fn signature(&mut self, sig: &Signature) {
        let takes_failure = sig.inputs.iter().any(|input| match input {
            FnArg::Typed(typed) => is_failure_type(&typed.ty),
            FnArg::Receiver(_) => false,
        });
        if takes_failure {
            self.names.insert(sig.ident.unraw().to_string());
        }
    }
}

impl<'ast> Visit<'ast> for Handlers {
    fn visit_item(&mut self, item: &'ast Item) {
        if !cfg_test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if !cfg_test_only(impl_item_attrs(item)) {
            visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if !cfg_test_only(trait_item_attrs(item)) {
            visit::visit_trait_item(self, item);
        }
    }

    fn visit_signature(&mut self, sig: &'ast Signature) {
        self.signature(sig);
        visit::visit_signature(self, sig);
    }
}

struct Scan<'h> {
    handlers: &'h BTreeSet<String>,
    /// The enclosing function names, innermost last.
    functions: Vec<String>,
    /// The bindings in scope, innermost last.
    scopes: Vec<BTreeMap<String, Binding>>,
    sites: Vec<(String, SiteKind)>,
}

impl<'h> Scan<'h> {
    fn new(handlers: &'h BTreeSet<String>) -> Self {
        Self {
            handlers,
            functions: Vec::new(),
            scopes: vec![BTreeMap::new()],
            sites: Vec::new(),
        }
    }

    fn record(&mut self, kind: SiteKind) {
        let function = self
            .functions
            .last()
            .map_or_else(|| OUTSIDE_FN.to_owned(), Clone::clone);
        self.sites.push((function, kind));
    }

    fn lookup(&self, name: &str) -> Binding {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).copied())
            .unwrap_or(Binding::Clean)
    }

    fn bind(&mut self, name: String, binding: Binding) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.insert(name, binding);
        }
    }

    fn push(&mut self) {
        self.scopes.push(BTreeMap::new());
    }

    fn pop(&mut self) {
        self.scopes.pop();
    }

    /// A function the renderer owns, or one whose parameter is the error.
    fn renders(&self, path: &Path) -> bool {
        last_name(path)
            .is_some_and(|name| listed(RENDERER_FNS, &name) || self.handlers.contains(&name))
    }

    fn binding_of(&self, expr: &Expr) -> Binding {
        match expr {
            Expr::Call(call) => self.call_binding(call),
            Expr::MethodCall(call) => self.method_binding(call),
            Expr::Path(path) if path.qself.is_none() => {
                path.path.get_ident().map_or(Binding::Clean, |ident| {
                    self.lookup(&ident.unraw().to_string())
                })
            }
            Expr::Paren(paren) => self.binding_of(&paren.expr),
            Expr::Group(group) => self.binding_of(&group.expr),
            Expr::Reference(reference) => self.binding_of(&reference.expr),
            Expr::Await(awaited) => self.binding_of(&awaited.base),
            Expr::Tuple(tuple) => {
                if tuple
                    .elems
                    .iter()
                    .any(|elem| self.binding_of(elem) == Binding::Outcome)
                {
                    Binding::Outcome
                } else {
                    Binding::Clean
                }
            }
            _ => Binding::Clean,
        }
    }

    fn call_binding(&self, call: &ExprCall) -> Binding {
        let serde = match &*call.func {
            Expr::Path(func) => serde_names(&func.path),
            _ => None,
        };
        if let Some(names) = serde {
            return if names.iter().any(|name| listed(STREAMS, name)) {
                Binding::Stream
            } else if names.last().is_some_and(|last| listed(FALLIBLE, last)) {
                Binding::Outcome
            } else {
                Binding::Clean
            };
        }
        if call
            .args
            .iter()
            .any(|arg| self.binding_of(arg) == Binding::Stream)
        {
            Binding::Outcome
        } else {
            Binding::Clean
        }
    }

    fn method_binding(&self, call: &ExprMethodCall) -> Binding {
        let receiver = self.binding_of(&call.receiver);
        if receiver == Binding::Stream
            || call
                .args
                .iter()
                .any(|arg| self.binding_of(arg) == Binding::Stream)
        {
            return Binding::Outcome;
        }
        let method = call.method.unraw().to_string();
        let drops = listed(DISCARDING, &method)
            || listed(ERROR_HANDLERS, &method)
            || listed(UNOPENED, &method);
        if receiver == Binding::Outcome && !drops {
            Binding::Outcome
        } else {
            Binding::Clean
        }
    }

    /// Bind every name `pat` introduces; `outcome` says the matched value is an
    /// outcome, `in_err` that the pattern sits under its `Err`.
    fn bind_pat(&mut self, pat: &Pat, outcome: bool, in_err: bool) {
        match pat {
            Pat::Ident(ident) => {
                let binding = if in_err {
                    Binding::Failure
                } else if outcome {
                    Binding::Outcome
                } else {
                    Binding::Clean
                };
                self.bind(ident.ident.unraw().to_string(), binding);
                if let Some((_, sub)) = &ident.subpat {
                    self.bind_pat(sub, outcome, in_err);
                }
            }
            Pat::TupleStruct(tuple) => {
                let err = outcome && last_name(&tuple.path).is_some_and(|name| name == "Err");
                for elem in &tuple.elems {
                    self.bind_pat(elem, false, in_err || err);
                }
            }
            Pat::Struct(fields) => {
                for field in &fields.fields {
                    self.bind_pat(&field.pat, false, in_err);
                }
            }
            Pat::Or(or) => {
                for case in &or.cases {
                    self.bind_pat(case, outcome, in_err);
                }
            }
            Pat::Tuple(tuple) => {
                for elem in &tuple.elems {
                    self.bind_pat(elem, outcome, in_err);
                }
            }
            Pat::Slice(slice) => {
                for elem in &slice.elems {
                    self.bind_pat(elem, outcome, in_err);
                }
            }
            Pat::Paren(paren) => self.bind_pat(&paren.pat, outcome, in_err),
            Pat::Reference(reference) => self.bind_pat(&reference.pat, outcome, in_err),
            Pat::Type(typed) => self.bind_pat(&typed.pat, outcome, in_err),
            Pat::Guard(guarded) => self.bind_pat(&guarded.pat, outcome, in_err),
            _ => {}
        }
    }

    /// Scan a function with fresh scopes, its `serde_json::Error` parameters
    /// bound as failures.
    fn function(&mut self, sig: &Signature, block: Option<&Block>) {
        let outer = std::mem::replace(&mut self.scopes, vec![BTreeMap::new()]);
        self.functions.push(sig.ident.unraw().to_string());
        self.visit_generics(&sig.generics);
        for input in &sig.inputs {
            match input {
                FnArg::Receiver(receiver) => self.visit_receiver(receiver),
                FnArg::Typed(typed) if is_failure_type(&typed.ty) => {
                    self.bind_pat(&typed.pat, false, true);
                }
                FnArg::Typed(typed) => {
                    self.bind_pat(&typed.pat, false, false);
                    self.visit_pat(&typed.pat);
                    self.visit_type(&typed.ty);
                }
            }
        }
        self.visit_return_type(&sig.output);
        if let Some(block) = block {
            self.visit_block(block);
        }
        self.functions.pop();
        self.scopes = outer;
    }

    /// Scan a closure; `failure` says its parameters are handed the error.
    fn closure(&mut self, closure: &ExprClosure, failure: bool) {
        self.push();
        for input in &closure.inputs {
            self.bind_pat(input, false, failure);
            self.visit_pat(input);
        }
        self.visit_return_type(&closure.output);
        self.visit_expr(&closure.body);
        self.pop();
    }

    /// The first argument of an error handler over an outcome.
    fn error_handler(&mut self, arg: &Expr) {
        match arg {
            Expr::Closure(closure) => self.closure(closure, true),
            Expr::Path(path) if self.renders(&path.path) => visit::visit_expr_path(self, path),
            _ => {
                self.record(SiteKind::Forwarded);
                self.visit_expr(arg);
            }
        }
    }

    fn visit_arg(&mut self, arg: &Expr) {
        if self.binding_of(arg) == Binding::Outcome {
            self.record(SiteKind::Forwarded);
        }
        self.visit_expr(arg);
    }

    /// Record a `Rendered` site for each `{name}` placeholder of `text` that
    /// names a failure binding.
    fn placeholders(&mut self, text: &str) {
        let mut rest = text;
        while let Some(open) = rest.find('{') {
            let after = rest.get(open.saturating_add(1)..).unwrap_or_default();
            if let Some(escaped) = after.strip_prefix('{') {
                rest = escaped;
                continue;
            }
            let end = after.find(['}', ':']).unwrap_or(after.len());
            let name = after.get(..end).unwrap_or_default().trim();
            if self.lookup(name) == Binding::Failure {
                self.record(SiteKind::Rendered);
            }
            rest = after;
        }
    }

    /// The token scan of a macro body that is not a list of expressions.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    if self.lookup(&ident.unraw().to_string()) == Binding::Failure {
                        self.record(SiteKind::Rendered);
                    }
                }
                TokenTree::Literal(literal) => {
                    let text = syn::parse2::<LitStr>(TokenTree::Literal(literal).into());
                    if let Ok(text) = text {
                        self.placeholders(&text.value());
                    }
                }
                TokenTree::Punct(_) => {}
            }
        }
    }

    fn add_use(&mut self, tree: &UseTree, under_serde: bool, owner: Option<&str>) {
        match tree {
            UseTree::Path(path) => {
                let name = path.ident.unraw().to_string();
                let under = under_serde || (owner.is_none() && name == SERDE_JSON);
                self.add_use(&path.tree, under, Some(&name));
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.add_use(item, under_serde, owner);
                }
            }
            UseTree::Glob(_) => {
                if under_serde {
                    self.record(SiteKind::Import);
                }
            }
            UseTree::Name(name) => {
                let name = name.ident.unraw().to_string();
                let module = name == "self" && owner.is_some_and(hidden);
                if under_serde && (hidden(&name) || module) {
                    self.record(SiteKind::Import);
                }
            }
            UseTree::Rename(rename) => {
                let name = rename.ident.unraw().to_string();
                let crate_rename = owner.is_none() && name == SERDE_JSON;
                let inner = under_serde && (hidden(&name) || name == "self");
                if crate_rename || inner {
                    self.record(SiteKind::Import);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
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

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.function(&item.sig, Some(item.block.as_ref()));
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.function(&item.sig, Some(&item.block));
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.function(&item.sig, item.default.as_ref());
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.add_use(&item.tree, false, None);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        if item.ident == SERDE_JSON && item.rename.is_some() {
            self.record(SiteKind::Import);
        }
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
        if cfg_test_only(&field.attrs) {
            return;
        }
        if self.binding_of(&field.expr) == Binding::Outcome {
            self.record(SiteKind::Forwarded);
        }
        visit::visit_field_value(self, field);
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

    fn visit_block(&mut self, block: &'ast Block) {
        self.push();
        visit::visit_block(self, block);
        self.pop();
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        let binding = local
            .init
            .as_ref()
            .map_or(Binding::Clean, |init| self.binding_of(&init.expr));
        match plain_ident(&local.pat) {
            Some(name) => self.bind(name, binding),
            None => self.bind_pat(&local.pat, binding == Binding::Outcome, false),
        }
        self.visit_pat(&local.pat);
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        self.closure(node, false);
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        self.visit_expr(&node.expr);
        let outcome = self.binding_of(&node.expr) == Binding::Outcome;
        for arm in node.arms.iter().filter(|arm| !cfg_test_only(&arm.attrs)) {
            self.push();
            self.bind_pat(&arm.pat, outcome, false);
            self.visit_pat(&arm.pat);
            self.visit_expr(&arm.body);
            self.pop();
        }
    }

    fn visit_expr_let(&mut self, node: &'ast ExprLet) {
        self.visit_expr(&node.expr);
        let outcome = self.binding_of(&node.expr) == Binding::Outcome;
        self.bind_pat(&node.pat, outcome, false);
        self.visit_pat(&node.pat);
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        self.push();
        self.visit_expr(&node.cond);
        self.visit_block(&node.then_branch);
        self.pop();
        if let Some((_, otherwise)) = &node.else_branch {
            self.visit_expr(otherwise);
        }
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.push();
        self.visit_expr(&node.cond);
        self.visit_block(&node.body);
        self.pop();
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.visit_expr(&node.expr);
        let binding = self.binding_of(&node.expr);
        self.push();
        match plain_ident(&node.pat) {
            Some(name) => self.bind(name, binding),
            None => self.bind_pat(&node.pat, binding == Binding::Outcome, false),
        }
        self.visit_pat(&node.pat);
        self.visit_block(&node.body);
        self.pop();
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if node.qself.is_none() {
            let failure = node
                .path
                .get_ident()
                .is_some_and(|ident| self.lookup(&ident.unraw().to_string()) == Binding::Failure);
            let fallible = serde_names(&node.path)
                .is_some_and(|names| names.last().is_some_and(|last| listed(FALLIBLE, last)));
            if failure {
                self.record(SiteKind::Rendered);
            } else if fallible {
                self.record(SiteKind::Forwarded);
            }
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        if is_carrier_path(path) {
            self.record(SiteKind::Carrier);
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_try(&mut self, node: &'ast ExprTry) {
        if self.binding_of(&node.expr) == Binding::Outcome {
            self.record(SiteKind::Forwarded);
        }
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if node
            .expr
            .as_ref()
            .is_some_and(|expr| self.binding_of(expr) == Binding::Outcome)
        {
            self.record(SiteKind::Forwarded);
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let renders = match &*node.func {
            Expr::Path(func) => {
                visit::visit_expr_path(self, func);
                self.renders(&func.path)
            }
            func => {
                self.visit_expr(func);
                false
            }
        };
        for arg in &node.args {
            if !(renders && self.binding_of(arg) == Binding::Failure) {
                self.visit_arg(arg);
            }
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.unraw().to_string();
        if self.binding_of(&node.receiver) == Binding::Failure && listed(INSPECTORS, &method) {
            for arg in &node.args {
                self.visit_arg(arg);
            }
            return;
        }
        let outcome = self.binding_of(&node.receiver) == Binding::Outcome;
        self.visit_expr(&node.receiver);
        if let Some(turbofish) = &node.turbofish {
            self.visit_angle_bracketed_generic_arguments(turbofish);
        }
        for (at, arg) in node.args.iter().enumerate() {
            if outcome && at == 0 && listed(ERROR_HANDLERS, &method) {
                self.error_handler(arg);
            } else {
                self.visit_arg(arg);
            }
        }
        if outcome && listed(UNOPENED, &method) {
            self.record(SiteKind::Forwarded);
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        match mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            Ok(args) => {
                for arg in &args {
                    if let Expr::Lit(ExprLit {
                        lit: Lit::Str(text),
                        ..
                    }) = arg
                    {
                        self.placeholders(&text.value());
                    } else {
                        self.visit_arg(arg);
                    }
                }
            }
            Err(_) => self.scan_tokens(mac.tokens.clone()),
        }
    }
}

/// The sites of every source, with the renderer handlers collected crate-wide;
/// a source that does not parse fails.
fn scan_all(sources: &[(String, String)]) -> Vec<(String, Vec<(String, SiteKind)>)> {
    let mut files = Vec::new();
    for (name, src) in sources {
        let parsed = syn::parse_file(src);
        assert!(
            parsed.is_ok(),
            "{name}: does not parse as Rust, so its serde error sites cannot be counted: {:?}",
            parsed.as_ref().err().map(ToString::to_string)
        );
        if let Ok(file) = parsed {
            files.push((name.clone(), file));
        }
    }
    let mut handlers = Handlers::default();
    for (_, file) in &files {
        handlers.visit_file(file);
    }
    files
        .iter()
        .map(|(name, file)| {
            let mut scan = Scan::new(&handlers.names);
            scan.visit_file(file);
            (name.clone(), scan.sites)
        })
        .collect()
}

/// The site count of the single source `src`, by function and kind.
fn scan(src: &str) -> BTreeMap<(String, SiteKind), usize> {
    let mut counts = BTreeMap::new();
    for (_, sites) in scan_all(&[("fixture.rs".to_owned(), src.to_owned())]) {
        for site in sites {
            let seen = counts.entry(site).or_insert(0_usize);
            *seen = seen.saturating_add(1);
        }
    }
    counts
}

/// Every unlisted site of `sources`, and every `ledger` entry whose count differs.
fn site_violations(sources: &[(String, String)], ledger: &[Admitted]) -> Vec<String> {
    let mut found: BTreeMap<(String, String, SiteKind), usize> = BTreeMap::new();
    for (name, sites) in scan_all(sources) {
        for (function, kind) in sites {
            let seen = found.entry((name.clone(), function, kind)).or_insert(0);
            *seen = seen.saturating_add(1);
        }
    }
    let mut out = Vec::new();
    for ((file, function, kind), seen) in &found {
        let entry = ledger.iter().find(|e| {
            e.file == file.as_str() && e.function == function.as_str() && e.kind == *kind
        });
        match entry {
            Some(entry) if entry.count == *seen => {}
            Some(entry) => out.push(format!(
                "{file}: {function}: {kind:?} expects {}, found {seen}",
                entry.count
            )),
            None => out.push(format!("{file}: {function}: {kind:?} unlisted ({seen})")),
        }
    }
    for entry in ledger {
        let key = (entry.file.to_owned(), entry.function.to_owned(), entry.kind);
        if !found.contains_key(&key) {
            out.push(format!(
                "{}: {}: {:?} expects {}, found 0",
                entry.file, entry.function, entry.kind, entry.count
            ));
        }
    }
    out
}

fn expect_sites(src: &str, kind: SiteKind, functions: &[&str]) {
    let expected: BTreeMap<(String, SiteKind), usize> = functions
        .iter()
        .map(|function| (((*function).to_owned(), kind), 1))
        .collect();
    assert_eq!(scan(src), expected);
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must catch or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn every_rendering_shape_is_a_site() {
    let src = r#"
fn a(s: &str) -> String {
    match serde_json::from_str::<V>(s) { Ok(_) => String::new(), Err(e) => format!("bad: {e}") }
}
fn b(s: &str) -> Result<V, String> { serde_json::from_str(s).map_err(|err| err.to_string()) }
fn c(s: &str) { if let Err(e) = serde_json::from_str::<V>(s) { log!("{}", e); } }
fn d(s: &str) {
    let parsed = serde_json::from_str::<V>(s);
    match parsed { Err(ref e) => warn!("{e:?}"), Ok(_) => {} }
}
fn e(v: &V) -> String { serde_json::to_string(v).unwrap_or_else(|e| e.to_string()) }
fn f(err: &serde_json::Error) -> String { format!("{err}") }
fn g(s: &str) { match (serde_json::from_str::<V>(s), 1) { (Err(e), _) => sink(e), _ => {} } }
fn h(s: &str, out: &mut String) {
    let mut de = serde_json::Deserializer::from_str(s);
    if let Err(e) = V::deserialize(&mut de) { let _ = write!(out, "{e}"); }
}
"#;
    expect_sites(
        src,
        SiteKind::Rendered,
        &["a", "b", "c", "d", "e", "f", "g", "h"],
    );
}

#[test]
fn every_forwarding_shape_is_a_site() {
    let src = r#"
fn a(s: &str) -> Result<V, Box<dyn std::error::Error>> { Ok(serde_json::from_str(s)?) }
fn b(s: &str) -> Result<V, E> { serde_json::from_str(s).map_err(E::Json) }
fn c(s: &str) { keep(serde_json::from_str::<V>(s)); }
fn d(s: &str) -> Option<String> { let r = serde_json::from_str::<V>(s); r.err().map(|_| String::new()) }
fn e() { let parse = serde_json::from_str::<V>; let _ = parse; }
fn f(s: &str) { warn!("{:?}", serde_json::from_str::<V>(s)); }
fn g(s: &str) -> W { W { inner: serde_json::from_str(s) } }
fn h(s: &str) -> R { return serde_json::from_str(s); }
fn i(s: &str) { let _ = serde_json::from_str::<V>(s).expect("valid"); }
"#;
    expect_sites(
        src,
        SiteKind::Forwarded,
        &["a", "b", "c", "d", "e", "f", "g", "h", "i"],
    );
}

#[test]
fn carriers_and_hidden_imports_are_sites() {
    let src = r"
use serde_json::from_str;
use serde_json::{Value, error::Error as JsonError};
use serde_json as sj;
use serde_json::*;
extern crate serde_json as json_crate;
use serde_json::{Value as JsonValue, json, Map};
extern crate serde_json;
enum E { Json(serde_json::Error) }
impl From<serde_json::Error> for E { fn from(_: serde_json::Error) -> Self { Self::Opaque } }
fn a() -> serde_json::Result<V> { load() }
";
    let expected: BTreeMap<(String, SiteKind), usize> = [
        ((OUTSIDE_FN.to_owned(), SiteKind::Import), 5),
        ((OUTSIDE_FN.to_owned(), SiteKind::Carrier), 2),
        (("a".to_owned(), SiteKind::Carrier), 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(scan(src), expected);
}

#[test]
fn admitted_shapes_are_not_sites() {
    let src = r#"
fn a(s: &str) -> IpeError {
    match serde_json::from_str::<V>(s) { Ok(_) => ok(), Err(e) => json_failure(&e) }
}
fn b(s: &str) -> Result<V, String> {
    serde_json::from_str(s).map_err(|e| json_failure_text(&e, JsonSource::Text))
}
fn c(s: &str) -> Kind {
    match serde_json::from_str::<V>(s) {
        Ok(_) => Kind::Fine,
        Err(e) if e.is_eof() => Kind::Short,
        Err(e) => kind_of(e.classify(), e.line(), e.column()),
    }
}
fn d(e: &serde_json::Error) -> Kind { classify_refusal(e) }
fn classify_refusal(err: &serde_json::Error) -> Kind { if err.is_eof() { Kind::Short } else { Kind::Bad } }
fn e(s: &str) -> Option<V> { serde_json::from_str(s).ok() }
fn f(v: &V) -> String { serde_json::to_string(v).unwrap_or_default() }
fn g(s: &str) -> Result<V, Refusal> { serde_json::from_str(s).map_err(|_| Refusal::Malformed) }
fn h(s: &str) -> String {
    match serde_json::from_str::<V>(s) { Ok(v) => format!("{v:?}"), Err(_) => String::new() }
}
fn i(s: &str) -> String { match s.parse::<u8>() { Ok(_) => String::new(), Err(e) => format!("{e}") } }
fn j(s: &str) -> String {
    if let Err(e) = serde_json::from_str::<V>(s) { let e = 7; return format!("{e}"); }
    String::new()
}
fn k(bytes: &[u8]) -> Result<V, Refusal> {
    let mut input = serde_json::Deserializer::from_slice(bytes);
    V::deserialize(&mut input)
        .and_then(|v| input.end().map(|()| v))
        .map_err(|_| Refusal::Malformed)
}
/// Logs `{e}` for a refusal.
fn l() -> &'static str { "{e}" }
fn m(s: &str) -> Result<V, Kind> { serde_json::from_str(s).map_err(classify_refusal) }
fn n(s: &str) -> String {
    match serde_json::from_str::<V>(s) { Ok(_) => String::new(), Err(e) => format!("{{e}}") }
}
#[cfg(test)]
mod tests {
    fn t(s: &str) -> String { serde_json::from_str::<V>(s).map_err(|e| e.to_string()).err().unwrap() }
}
"#;
    assert_eq!(scan(src), BTreeMap::new());
}

#[test]
fn an_unlisted_moved_or_stale_site_is_red() {
    let src = vec![(
        "x.rs".to_owned(),
        "fn a(v: &V) -> String { serde_json::to_string(v).unwrap_or_else(|e| e.to_string()) }"
            .to_owned(),
    )];
    let entry = |function: &'static str, count: usize| Admitted {
        file: "x.rs",
        function,
        kind: SiteKind::Rendered,
        count,
        reason: "fixture",
    };
    assert_eq!(
        site_violations(&src, &[entry("a", 1)]),
        Vec::<String>::new()
    );
    assert_eq!(
        site_violations(&src, &[]),
        vec!["x.rs: a: Rendered unlisted (1)"]
    );
    assert_eq!(
        site_violations(&src, &[entry("b", 1)]),
        vec![
            "x.rs: a: Rendered unlisted (1)",
            "x.rs: b: Rendered expects 1, found 0"
        ]
    );
    assert_eq!(
        site_violations(&src, &[entry("a", 2)]),
        vec!["x.rs: a: Rendered expects 2, found 1"]
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = scan("fn a( {");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// The runtime sources except the renderer, after checking the walk read the
/// files the ledger names and the renderer still defines its functions.
fn runtime_sources() -> Vec<(String, String)> {
    let root = e2e_support::manifest_dir!().join("src");
    let mut found = rust_sources(&root);
    for required in [
        RENDERER,
        "js_port.rs",
        "jwt.rs",
        "seal_codec.rs",
        "web/hub.rs",
        "web/store.rs",
    ] {
        assert!(
            found.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let renderer = found.iter().find(|(name, _)| name == RENDERER);
    for function in RENDERER_FNS {
        let defined = format!("fn {function}(");
        assert!(
            renderer.is_some_and(|(_, src)| src.contains(&defined)),
            "{RENDERER} no longer defines `{function}`"
        );
    }
    found.retain(|(name, _)| name != RENDERER);
    found
}

#[test]
fn a_planted_echo_in_the_runtime_tree_is_refused() {
    let mut tree = runtime_sources();
    let baseline = site_violations(&tree, ADMITTED_SITES);
    tree.push((
        "planted.rs".to_owned(),
        r#"pub fn leak(s: &str) -> String {
    match serde_json::from_str::<u8>(s) { Ok(_) => String::new(), Err(e) => format!("{e}") }
}"#
        .to_owned(),
    ));
    let planted = site_violations(&tree, ADMITTED_SITES);
    let refusal = "planted.rs: leak: Rendered unlisted (1)".to_owned();
    assert!(!baseline.contains(&refusal));
    assert!(planted.contains(&refusal));
    assert_eq!(planted.len(), baseline.len().saturating_add(1));
}

#[test]
fn serde_error_text_sites_are_admitted() {
    let tree = runtime_sources();
    let found = site_violations(&tree, ADMITTED_SITES);
    let census: Vec<String> = scan_all(&tree)
        .into_iter()
        .flat_map(|(file, sites)| {
            sites
                .into_iter()
                .map(move |(function, kind)| format!("{file}: {function}: {kind:?}"))
        })
        .collect();
    assert!(
        found.is_empty(),
        "a `serde_json::Error` becomes text only through `json::json_failure_text` (or \
         `json_failure`): a data error quotes the input it refused. Route the failure \
         through the renderer, or list a site that cannot carry input in \
         `ADMITTED_SITES` with its reason; a listed site must still exist:\n{}\n\n\
         every observed site:\n{}",
        found.join("\n"),
        census.join("\n")
    );
    assert!(
        ADMITTED_SITES.iter().all(|entry| !entry.reason.is_empty()),
        "every admitted site names its reason"
    );
}

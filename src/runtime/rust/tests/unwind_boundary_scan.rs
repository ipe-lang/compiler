//! Unwind-boundary scan: every place the runtime catches an unwind is ledgered,
//! and each one either types a runtime trip or runs no Ipê code.
//!
//! A [`RuntimeTrip`](ipe_runtime_rust::core::RuntimeTrip) raised deep inside
//! pure code reaches the program as its typed error only if no catch on the
//! way absorbs it or funnels it through the foreign-panic path. Every `.rs` file
//! under `src/` is parsed with `syn`, and each catch shape is counted per
//! enclosing function in production syntax: a `catch_unwind` path or method,
//! a `CatchPanicLayer` path, a `JoinError::try_into_panic`/`into_panic` call,
//! and a no-argument `.join()` (a thread `JoinHandle`, whose `Err` is the
//! payload). [`CATCH_SITES`] lists each `(file, fn, shape)` with its exact
//! count and its [`Route`]: a site that can see Ipê code must call the named
//! typed conversion in the same function, and a site that runs no Ipê code
//! says why. An unlisted site, a stale entry, and a typed route whose callee is
//! missing all go red.
//!
//! A `#[cfg(...)]` proven test-only removes exactly the node it is attached to;
//! a `use` names nothing; comments and string literals are never code. A macro
//! body is scanned token by token, so a shape written inside one still counts.
//! A path-form `join` qualified by a type (`JoinHandle::join(h)`, a type
//! alias's `Handle::join`, `<JoinHandle<()>>::join`) counts as a thread join,
//! whatever the type's name: an alias cannot hide it. A path call
//! `thread::scope` counts as a catch, since the scope joins its threads
//! implicitly and replaces a panicking one's payload with its own message. A
//! `use` that renames a catch name, a join-handle type or the `thread` module,
//! or that imports `scope` from `thread` (by name, rename or glob), is refused
//! outright: the scan matches names, so the import would hide every call made
//! through it.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprMethodCall, ExprPath, Field, FieldValue, ImplItem, ImplItemFn, Item,
    ItemFn, ItemUse, Macro, Path, Stmt, TraitItem, TraitItemFn, UseTree, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The name a site written outside any function is keyed under.
const OUTSIDE_FN: &str = "<outside any fn>";

/// The path segments and method names that catch an unwind.
const CATCH_NAMES: &[&str] = &[
    "catch_unwind",
    "CatchPanic",
    "CatchPanicLayer",
    "try_into_panic",
    "into_panic",
];

/// The shape a no-argument `.join()` call is recorded under.
const THREAD_JOIN: &str = "join()";

/// The thread-handle types a `use` must not rename.
const JOIN_HANDLES: &[&str] = &["JoinHandle", "ScopedJoinHandle"];

/// The shape a `thread::scope` call is recorded under: the scope joins every
/// thread it spawned and, when one panicked, unwinds with its own message in
/// place of that thread's payload, so a trip there would lose its type.
const THREAD_SCOPE: &str = "thread::scope";

/// Whether a path segment names a type (or `Self`): its `join` is a thread
/// join whatever the type is called, so a type alias cannot hide one.
fn names_a_type(segment: &str) -> bool {
    segment.chars().next().is_some_and(char::is_uppercase)
}

/// How a ledgered catch site treats a runtime trip.
#[derive(Debug, Clone, Copy)]
enum Route {
    /// The site can see Ipê code and calls this typed conversion in the same
    /// function, so a trip keeps its kind (or is resumed).
    Typed(&'static str),
    /// The site catches only runtime or library code, never an Ipê
    /// computation, so no trip can reach it; the text says what it catches.
    NoIpeCode(&'static str),
}

/// One ledgered catch site.
struct CatchSite {
    /// The file, relative to `src/`.
    file: &'static str,
    /// The enclosing function, or [`OUTSIDE_FN`].
    function: &'static str,
    /// The catch shape: one of [`CATCH_NAMES`], [`THREAD_JOIN`] or
    /// [`THREAD_SCOPE`].
    shape: &'static str,
    /// How many times `shape` occurs in `function`.
    count: usize,
    /// How the site treats a runtime trip.
    route: Route,
}

/// Every production catch site of the runtime, with how it treats a trip.
const CATCH_SITES: &[CatchSite] = &[
    CatchSite {
        file: "core.rs",
        function: "note_foreign_panic",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode(
            "drops an already-logged foreign payload whose own `Drop` may unwind",
        ),
    },
    CatchSite {
        file: "list.rs",
        function: "sort_by_total",
        shape: "catch_unwind",
        count: 1,
        route: Route::Typed("resume_runtime_trip"),
    },
    CatchSite {
        file: "server.rs",
        function: "insert_endpoint",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode("axum's route-registration panic on a conflicting path"),
    },
    CatchSite {
        file: "server.rs",
        function: "server_listen",
        shape: "CatchPanicLayer",
        count: 1,
        route: Route::Typed("panic_500_body"),
    },
    CatchSite {
        file: "system.rs",
        function: "probe_child_listener",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode("tokio's signal-driver registration panic"),
    },
    CatchSite {
        file: "system.rs",
        function: "request_spawn",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode("a child-process spawn on the spawner thread"),
    },
    CatchSite {
        file: "system.rs",
        function: "run_pre_exit_stages",
        shape: "catch_unwind",
        count: 3,
        route: Route::NoIpeCode(
            "the exit-time teardown (terminal-restore hook, exporter flush, console stop); \
             the process ends either way",
        ),
    },
    CatchSite {
        file: "system.rs",
        function: "run_spawn_jobs",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode("a spawner-thread job, which runs only runtime spawn code"),
    },
    CatchSite {
        file: "task.rs",
        function: "block_on",
        shape: THREAD_JOIN,
        count: 1,
        route: Route::Typed("entry_unwind_error"),
    },
    CatchSite {
        file: "task.rs",
        function: "drive_entry_caught",
        shape: "catch_unwind",
        count: 1,
        route: Route::Typed("entry_unwind_error"),
    },
    CatchSite {
        file: "task.rs",
        function: "ffi_spawn_guarded",
        shape: "try_into_panic",
        count: 1,
        route: Route::Typed("ipe_error_from_panic"),
    },
    CatchSite {
        file: "task.rs",
        function: "parallel_child_failure",
        shape: "try_into_panic",
        count: 1,
        route: Route::Typed("ipe_error_from_unwind"),
    },
    CatchSite {
        file: "threads.rs",
        function: "join_blocking",
        shape: "try_into_panic",
        count: 1,
        route: Route::Typed("resume_runtime_trip"),
    },
    CatchSite {
        file: "threads.rs",
        function: "offload_blocking",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode("tokio's blocking-pool thread-start panic, before `f` runs"),
    },
    CatchSite {
        file: "web/mod.rs",
        function: "build_web_router",
        shape: "CatchPanicLayer",
        count: 1,
        route: Route::Typed("panic_500_body"),
    },
    CatchSite {
        file: "web/mod.rs",
        function: "serve_page",
        shape: "try_into_panic",
        count: 1,
        route: Route::Typed("panic_500_body"),
    },
];

/// One file's catch sites and the names each function calls.
#[derive(Default)]
struct Found {
    /// `(fn, shape)` per catch occurrence.
    sites: Vec<(String, &'static str)>,
    /// Every path's last segment and method name, per function.
    calls: BTreeMap<String, BTreeSet<String>>,
    /// `(original, alias)` per `use` that renames a catch name or join handle.
    renames: Vec<(String, String)>,
}

/// The `syn` walk of one file's production syntax.
#[derive(Default)]
struct Scan {
    functions: Vec<String>,
    found: Found,
}

impl Scan {
    fn function(&self) -> String {
        self.functions
            .last()
            .map_or_else(|| OUTSIDE_FN.to_owned(), Clone::clone)
    }

    fn record(&mut self, shape: &'static str) {
        let function = self.function();
        self.found.sites.push((function, shape));
    }

    fn call(&mut self, name: String) {
        let function = self.function();
        self.found.calls.entry(function).or_default().insert(name);
    }

    fn catch_shape(name: &str) -> Option<&'static str> {
        CATCH_NAMES.iter().copied().find(|shape| *shape == name)
    }

    fn named(&mut self, name: &str) {
        if let Some(shape) = Self::catch_shape(name) {
            self.record(shape);
        }
        self.call(name.to_owned());
    }

    /// Count the catch shapes in a macro body, token by token.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(id) => {
                    let name = id.unraw().to_string();
                    let after_dot = at
                        .checked_sub(1)
                        .and_then(|before| trees.get(before))
                        .is_some_and(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == '.'));
                    let empty_call = matches!(
                        trees.get(at.saturating_add(1)),
                        Some(TokenTree::Group(g))
                            if g.delimiter() == Delimiter::Parenthesis && g.stream().is_empty()
                    );
                    if name == "join" && after_dot && empty_call {
                        self.record(THREAD_JOIN);
                    }
                    self.named(&name);
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
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

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        if cfg_test_only(&item.attrs) {
            return;
        }
        let mut pending: Vec<(&UseTree, Option<String>)> = vec![(&item.tree, None)];
        while let Some((tree, parent)) = pending.pop() {
            let from_thread = parent.as_deref() == Some("thread");
            match tree {
                UseTree::Path(path) => {
                    pending.push((&path.tree, Some(path.ident.unraw().to_string())));
                }
                UseTree::Group(group) => {
                    pending.extend(group.items.iter().map(|t| (t, parent.clone())));
                }
                UseTree::Rename(rename) => {
                    let named = rename.ident.unraw().to_string();
                    // `use std::thread::{self as t}` renames the module itself.
                    let original = if named == "self" {
                        parent.clone().unwrap_or(named)
                    } else {
                        named
                    };
                    let hidden = Self::catch_shape(&original).is_some()
                        || JOIN_HANDLES.contains(&original.as_str())
                        || original == "thread"
                        || (from_thread && original == "scope");
                    if hidden {
                        let alias = rename.rename.unraw().to_string();
                        self.found.renames.push((original, alias));
                    }
                }
                UseTree::Name(name) => {
                    if from_thread && name.ident.unraw() == "scope" {
                        self.found
                            .renames
                            .push(("thread::scope".to_owned(), "scope".to_owned()));
                    }
                }
                UseTree::Glob(_) => {
                    if from_thread {
                        self.found
                            .renames
                            .push(("thread::*".to_owned(), "*".to_owned()));
                    }
                }
            }
        }
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_item_fn(self, item);
        self.functions.pop();
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_impl_item_fn(self, item);
        self.functions.pop();
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.functions.push(item.sig.ident.unraw().to_string());
        visit::visit_trait_item_fn(self, item);
        self.functions.pop();
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

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.unraw().to_string();
        if name == "join" && call.args.is_empty() {
            self.record(THREAD_JOIN);
        }
        self.named(&name);
        visit::visit_expr_method_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let mut previous: Option<String> = None;
        for segment in &path.segments {
            let name = segment.ident.unraw().to_string();
            if let Some(shape) = Self::catch_shape(&name) {
                self.record(shape);
            }
            let handle_join = name == "join" && previous.as_deref().is_some_and(names_a_type);
            if handle_join {
                self.record(THREAD_JOIN);
            }
            if name == "scope" && previous.as_deref() == Some("thread") {
                self.record(THREAD_SCOPE);
            }
            previous = Some(name);
        }
        if let Some(last) = path.segments.last() {
            self.call(last.ident.unraw().to_string());
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        // `<JoinHandle<()>>::join`: the qualifying type sits in the `qself`,
        // so the path itself is the bare `join`.
        let qualified_join = expr.qself.is_some()
            && expr.path.segments.len() == 1
            && expr
                .path
                .segments
                .first()
                .is_some_and(|segment| segment.ident.unraw() == "join");
        if qualified_join {
            self.record(THREAD_JOIN);
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The scan of one source; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Found {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its catch sites cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut walk = Scan::default();
    if let Ok(file) = parsed {
        walk.visit_file(&file);
    }
    walk.found
}

/// Every difference between the catch sites of `sources` and `ledger`.
fn violations(sources: &[(String, String)], ledger: &[CatchSite]) -> Vec<String> {
    let mut counts: BTreeMap<(String, String, &'static str), usize> = BTreeMap::new();
    let mut calls: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut out = Vec::new();
    for (file, src) in sources {
        let found = scan(file, src);
        for (original, alias) in found.renames {
            out.push(format!(
                "{file}: `use .. {original} as {alias}` hides `{original}` from the scan: \
                 call it by its own name"
            ));
        }
        for (function, shape) in found.sites {
            let count = counts.entry((file.clone(), function, shape)).or_insert(0);
            *count = count.saturating_add(1);
        }
        for (function, names) in found.calls {
            calls.insert((file.clone(), function), names);
        }
    }
    for ((file, function, shape), count) in &counts {
        let listed = ledger.iter().find(|s| {
            s.file == file.as_str() && s.function == function.as_str() && s.shape == *shape
        });
        match listed {
            None => out.push(format!(
                "{file}: `{function}` catches an unwind through `{shape}` {count} time(s) \
                 unledgered: route the payload through `ipe_error_from_unwind` (or resume a \
                 `runtime_trip`) and add a `CATCH_SITES` row"
            )),
            Some(site) if site.count != *count => out.push(format!(
                "{file}: `{function}` `{shape}` occurs {count} time(s), ledgered {}",
                site.count
            )),
            Some(_) => {}
        }
    }
    for site in ledger {
        let key = (site.file.to_owned(), site.function.to_owned(), site.shape);
        if !counts.contains_key(&key) {
            out.push(format!(
                "{}: `{}` `{}` ledgered {} time(s), found 0 (stale entry)",
                site.file, site.function, site.shape, site.count
            ));
        }
        match site.route {
            Route::Typed(callee) => {
                let called = calls
                    .get(&(site.file.to_owned(), site.function.to_owned()))
                    .is_some_and(|names| names.contains(callee));
                if !called {
                    out.push(format!(
                        "{}: `{}` catches through `{}` but never calls `{callee}`",
                        site.file, site.function, site.shape
                    ));
                }
            }
            Route::NoIpeCode(what) => {
                if what.trim().is_empty() {
                    out.push(format!(
                        "{}: `{}` must say what its `{}` catches",
                        site.file, site.function, site.shape
                    ));
                }
            }
        }
    }
    out
}

fn sources(files: &[(&str, &str)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(name, src)| ((*name).to_owned(), (*src).to_owned()))
        .collect()
}

/// A one-row ledger for the fixtures.
const SORT_ONLY: &[CatchSite] = &[CatchSite {
    file: "list.rs",
    function: "sort_by_total",
    shape: "catch_unwind",
    count: 1,
    route: Route::Typed("resume_runtime_trip"),
}];

const LEDGERED_SORT: &str = r"
fn sort_by_total<T>(result: &mut [T]) {
    if let Err(p) = std::panic::catch_unwind(|| ()) {
        drop(crate::core::resume_runtime_trip(p));
    }
}
";

#[test]
fn a_ledgered_site_that_routes_its_trip_passes() {
    let found = violations(&sources(&[("list.rs", LEDGERED_SORT)]), SORT_ONLY);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_unledgered_catch_is_refused() {
    let src = r"
fn rogue() { let _ = std::panic::catch_unwind(|| ()); }
fn rogue_join(h: std::thread::JoinHandle<()>) { let _ = h.join(); }
fn rogue_task(e: tokio::task::JoinError) { let _ = e.into_panic(); }
fn rogue_layer() -> tower_http::catch_panic::CatchPanicLayer<F> { CatchPanicLayer::new() }
fn rogue_macro() { m!(x.join(); std::panic::catch_unwind(f)); }
";
    let found = violations(
        &sources(&[("list.rs", LEDGERED_SORT), ("rogue.rs", src)]),
        SORT_ONLY,
    );
    for (function, shape) in [
        ("rogue", "catch_unwind"),
        ("rogue_join", THREAD_JOIN),
        ("rogue_task", "into_panic"),
        ("rogue_layer", "CatchPanicLayer"),
        ("rogue_macro", THREAD_JOIN),
        ("rogue_macro", "catch_unwind"),
    ] {
        assert!(
            found
                .iter()
                .any(|v| v.contains(&format!("`{function}` catches an unwind through `{shape}`"))),
            "`{function}` `{shape}` must be refused: {found:#?}"
        );
    }
}

#[test]
fn a_path_join_and_a_renamed_catch_are_refused() {
    let src = r"
use std::panic::catch_unwind as contain;
use std::thread::{JoinHandle as Handle, spawn};
use tokio::task::JoinError;
fn via_alias() { let _ = contain(|| ()); }
fn via_path(h: std::thread::JoinHandle<()>) { let _ = std::thread::JoinHandle::join(h); }
fn via_map(hs: Vec<JoinHandle<()>>) { let _ = hs.into_iter().map(JoinHandle::join); }
";
    let found = violations(&sources(&[("rogue.rs", src)]), &[]);
    for needle in [
        "`use .. catch_unwind as contain`",
        "`use .. JoinHandle as Handle`",
        "`via_path` catches an unwind through `join()`",
        "`via_map` catches an unwind through `join()`",
    ] {
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "{needle} must be refused: {found:#?}"
        );
    }
    assert_eq!(found.len(), 4, "{found:#?}");
}

#[test]
fn an_aliased_or_qualified_join_a_scope_and_a_catch_service_are_refused() {
    let src = r"
use std::thread::scope as region;
use std::thread::{self as t};
use std::thread::scope;
use std::thread::*;
type Handle = std::thread::JoinHandle<()>;
fn via_type_alias(h: Handle) { let _ = Handle::join(h); }
fn via_qself(h: std::thread::JoinHandle<()>) { let _ = <std::thread::JoinHandle<()>>::join(h); }
fn via_scope() { std::thread::scope(|s| { s.spawn(|| ()); }); }
fn via_service<S>(inner: S) { let _ = tower_http::catch_panic::CatchPanic::new(inner); }
";
    let found = violations(&sources(&[("rogue.rs", src)]), &[]);
    for needle in [
        "`use .. scope as region`",
        "`use .. thread as t`",
        "`use .. thread::scope as scope`",
        "`use .. thread::* as *`",
        "`via_type_alias` catches an unwind through `join()`",
        "`via_qself` catches an unwind through `join()`",
        "`via_scope` catches an unwind through `thread::scope`",
        "`via_service` catches an unwind through `CatchPanic`",
    ] {
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "{needle} must be refused: {found:#?}"
        );
    }
    assert_eq!(found.len(), 8, "{found:#?}");
}

#[test]
fn a_typed_site_that_drops_its_route_is_refused() {
    let src = r"
fn sort_by_total<T>(result: &mut [T]) {
    let _ = std::panic::catch_unwind(|| ());
}
";
    let found = violations(&sources(&[("list.rs", src)]), SORT_ONLY);
    assert!(
        found
            .iter()
            .any(|v| v.contains("never calls `resume_runtime_trip`")),
        "{found:#?}"
    );
}

#[test]
fn a_stale_or_miscounted_entry_is_refused() {
    let stale = violations(&sources(&[("list.rs", "fn sort_by_total() {}")]), SORT_ONLY);
    assert!(
        stale.iter().any(|v| v.contains("(stale entry)")),
        "{stale:#?}"
    );
    let twice = r"
fn sort_by_total() {
    let _ = std::panic::catch_unwind(|| ());
    drop(resume_runtime_trip(std::panic::catch_unwind(|| ())));
}
";
    let miscounted = violations(&sources(&[("list.rs", twice)]), SORT_ONLY);
    assert!(
        miscounted
            .iter()
            .any(|v| v.contains("occurs 2 time(s), ledgered 1")),
        "{miscounted:#?}"
    );
}

#[test]
fn test_only_code_uses_and_text_are_not_sites() {
    let src = r#"
use std::panic::catch_unwind;
/// catch_unwind in a doc comment.
// catch_unwind in a line comment.
fn text() -> &'static str { "catch_unwind CatchPanicLayer x.join()" }
fn joined(parts: &[&str]) -> String { parts.join(",") }
#[cfg(test)]
mod tests { fn t() { let _ = std::panic::catch_unwind(|| ()); } }
#[cfg(all(test, feature = "x"))]
fn gated() { let _ = std::panic::catch_unwind(|| ()); }
"#;
    let found = violations(&sources(&[("plain.rs", src)]), &[]);
    assert!(found.is_empty(), "{found:#?}");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

#[test]
fn every_runtime_catch_site_is_ledgered_and_routed() {
    let root = e2e_support::manifest_dir!().join("src");
    let found = rust_sources(&root);
    for required in ["core.rs", "list.rs", "task.rs", "web/mod.rs"] {
        assert!(
            found.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let violations = violations(&found, CATCH_SITES);
    assert!(
        violations.is_empty(),
        "unwind-boundary scan:\n{}",
        violations.join("\n")
    );
}

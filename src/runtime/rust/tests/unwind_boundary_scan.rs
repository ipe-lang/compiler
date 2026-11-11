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
//! count and its [`Route`]: a site that can see Ipê code must hand the caught
//! payload to the named typed conversion in the same function, and a site that
//! runs no Ipê code says why. An unlisted site, a stale entry, and a typed route
//! whose callee never receives the payload all go red.
//!
//! The same walk keys every async-task start and join on its operation: a call,
//! a path or a method named in [`TASK_OPS`], on any receiver and outside the
//! [`FUNNEL_FILES`], is a site that [`TASK_SITES`] must list exactly, so a task
//! starts and joins only through `threads::spawn_task` and `IpeJoinSet`. An
//! `#[allow]` or `#[expect]` of `clippy::disallowed_types` outside the funnel
//! is refused, since it would silence the type-resolved `JoinSet` ban.
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
    Arm, Attribute, Expr, ExprCall, ExprMethodCall, ExprPath, Field, FieldValue, ImplItem,
    ImplItemFn, Item, ItemFn, ItemUse, Local, Macro, Pat, PatIdent, Path, Stmt, TraitItem,
    TraitItemFn, UseTree, Variant,
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

/// The last path segments and method names that start or join an async task.
const TASK_OPS: &[&str] = &[
    "spawn",
    "spawn_on",
    "spawn_local",
    "spawn_local_on",
    "spawn_blocking_on",
    "join_next",
    "try_join_next",
    "join_next_with_id",
    "join_all",
    "spawn_unmigrated",
    "spawn_in_current_scope",
];

/// The files that hold the task funnel; their task operations are its own.
const FUNNEL_FILES: &[&str] = &["threads.rs"];

/// The file that names each path the runtime `clippy.toml` denies. Its task
/// paths name a denied path and start nothing, so it is exempt only while it
/// holds nothing but such namings (see [`names_paths_only`]).
const PATH_NAMING_FILE: &str = "clippy_paths_resolve.rs";

/// Whether `src` holds only `const _X: () = { let _ = <path>; .. };` items:
/// each names a path and evaluates nothing, so no task can start in it.
fn names_paths_only(src: &str) -> bool {
    let Ok(file) = syn::parse_file(src) else {
        return false;
    };
    file.items.iter().all(|item| {
        let Item::Const(konst) = item else {
            return false;
        };
        let unit = matches!(&*konst.ty, syn::Type::Tuple(t) if t.elems.is_empty());
        let Expr::Block(body) = &*konst.expr else {
            return false;
        };
        unit && konst.ident.to_string().starts_with('_')
            && body.block.stmts.iter().all(|stmt| {
                let Stmt::Local(local) = stmt else {
                    return false;
                };
                let wild = match &local.pat {
                    Pat::Wild(_) => true,
                    Pat::Type(typed) => matches!(&*typed.pat, Pat::Wild(_)),
                    _ => false,
                };
                wild && local.init.as_ref().is_some_and(|init| {
                    init.diverge.is_none() && matches!(&*init.expr, Expr::Path(_))
                })
            })
    })
}

/// The files whose raw task sites the next migration slice moves onto the
/// funnel; only they may hold a [`TaskRoute::Unmigrated`] row.
const UNMIGRATED_FILES: &[&str] = &[
    "tea.rs",
    "system.rs",
    "web/console_proxy.rs",
    "task.rs",
    "ws_client.rs",
];

/// The directory prefix whose files the next migration slice also moves.
const UNMIGRATED_DIR: &str = "debugger/";

/// How a ledgered task site stands to the funnel.
#[derive(Debug, Clone, Copy)]
enum TaskRoute {
    /// The name is not a task operation here (an OS-thread or child-process
    /// start, a closure parameter called `spawn`); the text says what it is.
    NotATask(&'static str),
    /// A raw start the next migration slice moves onto the funnel.
    Unmigrated,
    /// A task on a target with no unwind, so no trip can be typed there; the
    /// text says why.
    NoUnwind(&'static str),
}

/// One ledgered task site.
struct TaskSite {
    /// The file, relative to `src/`.
    file: &'static str,
    /// The enclosing function, or [`OUTSIDE_FN`].
    function: &'static str,
    /// The operation: one of [`TASK_OPS`].
    op: &'static str,
    /// How many times `op` occurs in `function`.
    count: usize,
    /// How the site stands to the funnel.
    route: TaskRoute,
}

/// What a `wasm32` task start answers for a trip.
const WASM_NO_UNWIND: &str = "wasm32 has no unwind: a trip traps the instance";

/// A Sub source's start closure, which the binding names `spawn`.
const SOURCE_START: &str = "a Sub source's start closure, called by its binding's name";

/// Every task-operation name outside the funnel, with how it stands to it.
const TASK_SITES: &[TaskSite] = &[
    TaskSite {
        file: "system.rs",
        function: OUTSIDE_FN,
        op: "spawn",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "system.rs",
        function: "request_spawn",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask("the spawner job's closure parameter"),
    },
    TaskSite {
        file: "system.rs",
        function: "spawn_hardened_on",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask("`std::process::Command::spawn`, a child process"),
    },
    TaskSite {
        file: "system.rs",
        function: "spawn_hardened_tokio",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask("`tokio::process::Command::spawn`, a child process"),
    },
    TaskSite {
        file: "system.rs",
        function: "spawner",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask("`std::thread::Builder::spawn`, the spawner's OS thread"),
    },
    TaskSite {
        file: "task.rs",
        function: "spawn_in_current_scope",
        op: "spawn_unmigrated",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "tea.rs",
        function: "add",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask(SOURCE_START),
    },
    TaskSite {
        file: "tea.rs",
        function: "apply",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask(SOURCE_START),
    },
    TaskSite {
        file: "tea.rs",
        function: "apply",
        op: "spawn_in_current_scope",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "tea.rs",
        function: "cli_run_cmd_tracked",
        op: "spawn_in_current_scope",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "tea.rs",
        function: "start_source",
        op: "spawn_in_current_scope",
        count: 2,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "tea.rs",
        function: "sub_map_arc",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask(SOURCE_START),
    },
    TaskSite {
        file: "tea.rs",
        function: "sub_map_rc",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask(SOURCE_START),
    },
    TaskSite {
        file: "tea.rs",
        function: "worker_run_cmd",
        op: "spawn_in_current_scope",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
    TaskSite {
        file: "wasm/mod.rs",
        function: "enqueue",
        op: "spawn_local",
        count: 1,
        route: TaskRoute::NoUnwind(WASM_NO_UNWIND),
    },
    TaskSite {
        file: "wasm/mod.rs",
        function: "run_cmd",
        op: "spawn_local",
        count: 1,
        route: TaskRoute::NoUnwind(WASM_NO_UNWIND),
    },
    TaskSite {
        file: "wasm/mod.rs",
        function: "run_start",
        op: "spawn_local",
        count: 1,
        route: TaskRoute::NoUnwind(WASM_NO_UNWIND),
    },
    TaskSite {
        file: "wasm/subs.rs",
        function: "update",
        op: "spawn",
        count: 1,
        route: TaskRoute::NotATask(SOURCE_START),
    },
    TaskSite {
        file: "ws_client.rs",
        function: "start_socket",
        op: "spawn",
        count: 1,
        route: TaskRoute::Unmigrated,
    },
];

/// How a ledgered catch site treats a runtime trip.
#[derive(Debug, Clone, Copy)]
enum Route {
    /// The site can see Ipê code and hands the caught payload to this typed
    /// conversion in the same function, so a trip keeps its kind (or is
    /// resumed).
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
        function: "run_guarded",
        shape: "catch_unwind",
        count: 1,
        route: Route::NoIpeCode(
            "the exit-time stages (terminal restore, line close, session dump, exporter \
             flush, console stop); the process ends either way",
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
        file: "threads.rs",
        function: "classify",
        shape: "try_into_panic",
        count: 1,
        route: Route::Typed("closure_unwind"),
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
];

/// One file's catch and task sites and the names each function calls.
#[derive(Default)]
struct Found {
    /// `(fn, shape)` per catch occurrence.
    sites: Vec<(String, &'static str)>,
    /// Every path's last segment and method name, per function.
    calls: BTreeMap<String, BTreeSet<String>>,
    /// Per function, every callee handed a caught payload (or a catch itself).
    routed: BTreeMap<String, BTreeSet<String>>,
    /// `(original, alias)` per `use` that renames a catch name or join handle.
    renames: Vec<(String, String)>,
    /// `(fn, op)` per task-operation occurrence.
    tasks: Vec<(String, &'static str)>,
    /// `(original, alias)` per `use` that renames a task operation.
    task_renames: Vec<(String, String)>,
}

/// The `syn` walk of one file's production syntax.
#[derive(Default)]
struct Scan {
    functions: Vec<String>,
    found: Found,
    /// Per function, the bindings that hold a caught payload.
    tainted: BTreeMap<String, BTreeSet<String>>,
}

/// Whether an expression holds a catch or names a binding of `tainted`.
struct Touch<'t> {
    tainted: &'t BTreeSet<String>,
    hit: bool,
}

impl<'ast> Visit<'ast> for Touch<'_> {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.unraw().to_string();
        if Scan::catch_shape(&name).is_some() || (name == "join" && call.args.is_empty()) {
            self.hit = true;
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        if let Some(segment) = expr.path.segments.first()
            && expr.path.segments.len() == 1
            && self.tainted.contains(&segment.ident.unraw().to_string())
        {
            self.hit = true;
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        if path
            .segments
            .iter()
            .any(|segment| Scan::catch_shape(&segment.ident.unraw().to_string()).is_some())
        {
            self.hit = true;
        }
        visit::visit_path(self, path);
    }
}

/// Every binding a pattern introduces.
#[derive(Default)]
struct Binders(Vec<String>);

impl<'ast> Visit<'ast> for Binders {
    fn visit_pat_ident(&mut self, pat: &'ast PatIdent) {
        self.0.push(pat.ident.unraw().to_string());
        visit::visit_pat_ident(self, pat);
    }
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
        self.task(name);
        self.call(name.to_owned());
    }

    /// Record `name` as a task site when it is a task operation.
    fn task(&mut self, name: &str) {
        if let Some(op) = TASK_OPS.iter().copied().find(|op| *op == name) {
            let function = self.function();
            self.found.tasks.push((function, op));
        }
    }

    /// Whether `expr` holds a catch or a binding that holds a caught payload.
    fn touches(&self, expr: &Expr) -> bool {
        let empty = BTreeSet::new();
        let tainted = self.tainted.get(&self.function()).unwrap_or(&empty);
        let mut touch = Touch {
            tainted,
            hit: false,
        };
        touch.visit_expr(expr);
        touch.hit
    }

    /// Mark every binding `pat` introduces as holding a caught payload.
    fn taint(&mut self, pat: &Pat) {
        let mut binders = Binders::default();
        binders.visit_pat(pat);
        let function = self.function();
        self.tainted.entry(function).or_default().extend(binders.0);
    }

    /// Mark the parameters of every closure in `args` as holding a caught
    /// payload.
    fn taint_closures<'a>(&mut self, args: impl Iterator<Item = &'a Expr>) {
        for arg in args {
            if let Expr::Closure(closure) = arg {
                for input in &closure.inputs {
                    self.taint(input);
                }
            }
        }
    }

    /// Record `callee` as handed a caught payload when any of `args` holds one.
    fn route<'a>(&mut self, callee: String, mut args: impl Iterator<Item = &'a Expr>) {
        if args.any(|arg| self.touches(arg)) {
            let function = self.function();
            self.found
                .routed
                .entry(function)
                .or_default()
                .insert(callee);
        }
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
                    let alias = rename.rename.unraw().to_string();
                    if TASK_OPS.contains(&original.as_str()) {
                        self.found
                            .task_renames
                            .push((original.clone(), alias.clone()));
                    }
                    if hidden {
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

    fn visit_local(&mut self, local: &'ast Local) {
        if local
            .init
            .as_ref()
            .is_some_and(|init| self.touches(&init.expr))
        {
            self.taint(&local.pat);
        }
        visit::visit_local(self, local);
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
        match expr {
            Expr::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            Expr::Let(binding) if self.touches(&binding.expr) => self.taint(&binding.pat),
            Expr::Match(matched) if self.touches(&matched.expr) => {
                for arm in &matched.arms {
                    self.taint(&arm.pat);
                }
            }
            _ => {}
        }
        visit::visit_expr(self, expr);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if self.touches(&call.func) {
            self.taint_closures(call.args.iter());
        }
        if let Expr::Path(func) = &*call.func
            && let Some(last) = func.path.segments.last()
        {
            self.route(last.ident.unraw().to_string(), call.args.iter());
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = call.method.unraw().to_string();
        if name == "join" && call.args.is_empty() {
            self.record(THREAD_JOIN);
        }
        self.named(&name);
        if self.touches(&call.receiver) {
            self.taint_closures(call.args.iter());
        }
        self.route(
            name,
            std::iter::once(&*call.receiver).chain(call.args.iter()),
        );
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
            let name = last.ident.unraw().to_string();
            self.task(&name);
            self.call(name);
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
    let mut routed: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
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
        for (function, callees) in found.routed {
            routed.insert((file.clone(), function), callees);
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
                let handed = routed
                    .get(&(site.file.to_owned(), site.function.to_owned()))
                    .is_some_and(|callees| callees.contains(callee));
                if !handed {
                    out.push(format!(
                        "{}: `{}` catches through `{}` but never hands its payload to `{callee}`",
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

/// Whether an attribute's tokens name `disallowed_types` under an `allow`,
/// an `expect`, or a `cfg_attr` that may expand to one.
fn silences_disallowed_types(attr: &Attribute) -> bool {
    fn names(tokens: TokenStream) -> bool {
        tokens.into_iter().any(|tree| match tree {
            TokenTree::Ident(id) => id.unraw() == "disallowed_types",
            TokenTree::Group(group) => names(group.stream()),
            TokenTree::Punct(_) | TokenTree::Literal(_) => false,
        })
    }
    let lint_level = ["allow", "expect", "cfg_attr"]
        .iter()
        .any(|level| attr.path().is_ident(level));
    lint_level
        && match &attr.meta {
            syn::Meta::List(list) => names(list.tokens.clone()),
            syn::Meta::Path(_) | syn::Meta::NameValue(_) => false,
        }
}

/// Every attribute of a file, test code included, that silences
/// `disallowed_types`.
#[derive(Default)]
struct LintAllows(usize);

impl<'ast> Visit<'ast> for LintAllows {
    fn visit_attribute(&mut self, attr: &'ast Attribute) {
        if silences_disallowed_types(attr) {
            self.0 = self.0.saturating_add(1);
        }
    }
}

/// How many attributes of `src` silence `disallowed_types`.
fn disallowed_type_allows(name: &str, src: &str) -> usize {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its lint attributes cannot be read"
    );
    let mut walk = LintAllows::default();
    if let Ok(file) = parsed {
        walk.visit_file(&file);
    }
    walk.0
}

/// Whether `file` is one the next migration slice moves onto the funnel.
fn awaits_migration(file: &str) -> bool {
    UNMIGRATED_FILES.contains(&file) || file.starts_with(UNMIGRATED_DIR)
}

/// Every difference between the task sites of `sources` and `ledger`.
fn task_violations(sources: &[(String, String)], ledger: &[TaskSite]) -> Vec<String> {
    let mut counts: BTreeMap<(String, String, &'static str), usize> = BTreeMap::new();
    let mut out = Vec::new();
    for (file, src) in sources {
        if FUNNEL_FILES.contains(&file.as_str()) {
            continue;
        }
        if file == PATH_NAMING_FILE {
            if names_paths_only(src) {
                continue;
            }
            out.push(format!(
                "{file}: holds an item other than a `const _X: () = {{ let _ = <path>; }}` \
                 naming, so it may start a task the scan exempts: keep it to namings"
            ));
        }
        let allows = disallowed_type_allows(file, src);
        if allows > 0 {
            out.push(format!(
                "{file}: {allows} attribute(s) silence `clippy::disallowed_types`, which bans \
                 a raw `JoinSet` outside `threads.rs`: join through `threads::IpeJoinSet`"
            ));
        }
        let found = scan(file, src);
        for (original, alias) in found.task_renames {
            out.push(format!(
                "{file}: `use .. {original} as {alias}` hides a task operation from the scan: \
                 call it by its own name"
            ));
        }
        for (function, op) in found.tasks {
            let count = counts.entry((file.clone(), function, op)).or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    for ((file, function, op), count) in &counts {
        let listed = ledger
            .iter()
            .find(|s| s.file == file.as_str() && s.function == function.as_str() && s.op == *op);
        match listed {
            None => out.push(format!(
                "{file}: `{function}` starts or joins a task through `{op}` {count} time(s) \
                 unledgered: start it through `threads::spawn_task` (join a set through \
                 `threads::IpeJoinSet`), or add a `TASK_SITES` row saying why it is not a task"
            )),
            Some(site) if site.count != *count => out.push(format!(
                "{file}: `{function}` `{op}` occurs {count} time(s), ledgered {}",
                site.count
            )),
            Some(_) => {}
        }
    }
    for site in ledger {
        let key = (site.file.to_owned(), site.function.to_owned(), site.op);
        if !counts.contains_key(&key) {
            out.push(format!(
                "{}: `{}` `{}` ledgered {} time(s), found 0 (stale entry)",
                site.file, site.function, site.op, site.count
            ));
        }
        match site.route {
            TaskRoute::Unmigrated if !awaits_migration(site.file) => out.push(format!(
                "{}: `{}` `{}` is ledgered unmigrated outside the files the next slice migrates",
                site.file, site.function, site.op
            )),
            TaskRoute::NotATask(what) | TaskRoute::NoUnwind(what) if what.trim().is_empty() => {
                out.push(format!(
                    "{}: `{}` must say why its `{}` is not a funnel start",
                    site.file, site.function, site.op
                ));
            }
            TaskRoute::Unmigrated | TaskRoute::NotATask(_) | TaskRoute::NoUnwind(_) => {}
        }
    }
    out
}

/// The task-local scopes the caller carrier must wrap a task in.
const CARRIED_SCOPES: &[&str] = &[
    "carry_web_session",
    "carry_request_streams",
    "carry_server_request",
];

/// Every scope the caller carrier of `task.rs` drops, and every carry the
/// `block_on` entry thread skips.
fn carrier_gaps(sources: &[(String, String)]) -> Vec<String> {
    let Some((_, src)) = sources.iter().find(|(name, _)| name == "task.rs") else {
        return vec!["task.rs: not read, so the caller carrier cannot be checked".to_owned()];
    };
    let calls = scan("task.rs", src).calls;
    let empty = BTreeSet::new();
    let carrier = calls.get("on_behalf_of_caller").unwrap_or(&empty);
    let mut out: Vec<String> = CARRIED_SCOPES
        .iter()
        .filter(|scope| !carrier.contains(**scope))
        .map(|scope| {
            format!(
                "task.rs: `on_behalf_of_caller` never calls `{scope}`, so a task drops that scope"
            )
        })
        .collect();
    out.extend(block_on_carry_gaps(src));
    out
}

/// The calls and method calls named `name` in a syntax node.
struct CallsNamed<'n> {
    name: &'n str,
    count: usize,
}

impl<'ast> Visit<'ast> for CallsNamed<'_> {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(callee) = &*call.func
            && callee
                .path
                .segments
                .last()
                .is_some_and(|s| s.ident == self.name)
        {
            self.count = self.count.saturating_add(1);
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == self.name {
            self.count = self.count.saturating_add(1);
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn calls_named(stmts: &[Stmt], name: &str) -> usize {
    let mut walk = CallsNamed { name, count: 0 };
    for stmt in stmts {
        walk.visit_stmt(stmt);
    }
    walk.count
}

/// Whether a syntax node binds or assigns `name`.
struct Rebinds<'n> {
    name: &'n syn::Ident,
    found: bool,
}

impl<'ast> Visit<'ast> for Rebinds<'_> {
    fn visit_pat_ident(&mut self, pat: &'ast PatIdent) {
        self.found |= pat.ident == *self.name;
        visit::visit_pat_ident(self, pat);
    }

    fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
        self.found |= matches!(&*assign.left, Expr::Path(p) if p.path.is_ident(self.name));
        visit::visit_expr_assign(self, assign);
    }
}

/// Whether `stmt` is `let <param> = on_behalf_of_caller(<param>);`.
fn carries_param(stmt: &Stmt, param: &syn::Ident) -> bool {
    let Stmt::Local(local) = stmt else {
        return false;
    };
    let Pat::Ident(bound) = &local.pat else {
        return false;
    };
    let Some(init) = local.init.as_ref().filter(|init| init.diverge.is_none()) else {
        return false;
    };
    let Expr::Call(call) = &*init.expr else {
        return false;
    };
    let carrier = matches!(&*call.func, Expr::Path(f) if f.path.segments.last().is_some_and(|s| s.ident == "on_behalf_of_caller"));
    let mut args = call.args.iter();
    let of_param =
        matches!((args.next(), args.next()), (Some(Expr::Path(a)), None) if a.path.is_ident(param));
    bound.ident == *param && bound.subpat.is_none() && carrier && of_param
}

/// Every way the `block_on` entry of `src` can start its entry thread on a
/// future that does not carry the caller's scope.
///
/// Exactly one top-level `block_on` spawns through `spawn_sized`, once, and a
/// statement before that spawn shadows its future parameter with
/// `on_behalf_of_caller` of itself, with no rebinding of the name between.
fn block_on_carry_gaps(src: &str) -> Vec<String> {
    let Ok(file) = syn::parse_file(src) else {
        return vec!["task.rs: does not parse, so `block_on` cannot be checked".to_owned()];
    };
    let entries: Vec<&ItemFn> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(f)
                if f.sig.ident == "block_on" && calls_named(&f.block.stmts, "spawn_sized") > 0 =>
            {
                Some(f)
            }
            _ => None,
        })
        .collect();
    let [entry] = entries.as_slice() else {
        return vec![format!(
            "task.rs: {} top-level `block_on` entries start their thread through \
             `spawn_sized`; exactly one must, so its carry can be checked",
            entries.len()
        )];
    };
    let stmts = &entry.block.stmts;
    let spawns = calls_named(stmts, "spawn_sized");
    if spawns != 1 {
        return vec![format!(
            "task.rs: `block_on` calls `spawn_sized` {spawns} times; one carried start is checked"
        )];
    }
    let param = entry.sig.inputs.first().and_then(|arg| match arg {
        syn::FnArg::Typed(typed) => match &*typed.pat {
            Pat::Ident(p) => Some(p.ident.clone()),
            _ => None,
        },
        syn::FnArg::Receiver(_) => None,
    });
    let Some(param) = param else {
        return vec!["task.rs: `block_on` takes no named future to carry".to_owned()];
    };
    let carried = stmts.iter().position(|stmt| carries_param(stmt, &param));
    let spawned = stmts
        .iter()
        .position(|stmt| calls_named(std::slice::from_ref(stmt), "spawn_sized") > 0);
    let (Some(carried), Some(spawned)) = (carried, spawned) else {
        return vec![format!(
            "task.rs: `block_on` never carries its future through \
             `let {param} = on_behalf_of_caller({param});`, so its entry thread drops \
             the caller's scope"
        )];
    };
    if carried >= spawned {
        return vec![format!(
            "task.rs: `block_on` carries `{param}` after the `spawn_sized` start, so the \
             entry thread runs the uncarried future"
        )];
    }
    let mut rebinds = Rebinds {
        name: &param,
        found: false,
    };
    for stmt in stmts
        .get(carried.saturating_add(1)..spawned)
        .unwrap_or_default()
    {
        rebinds.visit_stmt(stmt);
    }
    if rebinds.found {
        return vec![format!(
            "task.rs: `block_on` rebinds `{param}` between its carry and the `spawn_sized` \
             start, so the entry thread may run an uncarried future"
        )];
    }
    Vec::new()
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
            .any(|v| v.contains("never hands its payload to `resume_runtime_trip`")),
        "{found:#?}"
    );
}

#[test]
fn a_typed_callee_that_never_sees_the_payload_is_refused() {
    let src = r"
fn sort_by_total<T>(result: &mut [T]) {
    let caught = std::panic::catch_unwind(|| ());
    drop(crate::core::resume_runtime_trip(Box::new(0)));
    drop(caught);
}
";
    let found = violations(&sources(&[("list.rs", src)]), SORT_ONLY);
    assert!(
        found
            .iter()
            .any(|v| v.contains("never hands its payload to `resume_runtime_trip`")),
        "{found:#?}"
    );
    let handed = r"
fn sort_by_total<T>(result: &mut [T]) {
    match std::panic::catch_unwind(|| ()) {
        Ok(()) => {}
        Err(caught) => {
            let held = caught;
            drop(crate::core::resume_runtime_trip(held));
        }
    }
}
";
    let found = violations(&sources(&[("list.rs", handed)]), SORT_ONLY);
    assert!(found.is_empty(), "{found:#?}");
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

// ---------------------------------------------------------------------------
// Every async-task start and join goes through the funnel.
// ---------------------------------------------------------------------------

/// A one-row task ledger for the fixtures.
const SOCKET_ONLY: &[TaskSite] = &[TaskSite {
    file: "ws_client.rs",
    function: "start_socket",
    op: "spawn",
    count: 1,
    route: TaskRoute::Unmigrated,
}];

#[test]
fn a_funnel_file_and_a_ledgered_site_pass() {
    let funnel = r"
fn spawn_task() { let _ = tokio::runtime::Handle::current().spawn(async {}); }
#[allow(clippy::disallowed_types)]
struct IpeJoinSet(tokio::task::JoinSet<()>);
";
    let socket = r#"
fn start_socket() { tokio::spawn(async {}); }
fn text() -> &'static str { "tokio::spawn( x.join_next()" }
#[cfg(test)]
mod tests { fn t() { tokio::spawn(async {}); } }
"#;
    let found = task_violations(
        &sources(&[("threads.rs", funnel), ("ws_client.rs", socket)]),
        SOCKET_ONLY,
    );
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn a_raw_task_start_and_its_evasions_are_refused() {
    let src = r"
use tokio::spawn as go;
type Set = tokio::task::JoinSet<()>;
fn via_rename() { go(async {}); }
fn via_alias(set: &mut Set) { set.spawn(async {}); let _ = set.join_next(); }
fn via_qself() { let _ = <tokio::task::JoinSet<()>>::spawn; }
fn via_handle() { tokio::runtime::Handle::current().spawn(async {}); }
fn via_macro() { m!(tokio::spawn(async {})); }
#[expect(clippy::disallowed_types)]
fn silenced() {}
#[cfg(test)]
mod tests { fn t() { tokio::spawn(async {}); } }
";
    let found = task_violations(&sources(&[("rogue.rs", src)]), &[]);
    for needle in [
        "`use .. spawn as go`",
        "`via_alias` starts or joins a task through `spawn`",
        "`via_alias` starts or joins a task through `join_next`",
        "`via_qself` starts or joins a task through `spawn`",
        "`via_handle` starts or joins a task through `spawn`",
        "`via_macro` starts or joins a task through `spawn`",
        "1 attribute(s) silence `clippy::disallowed_types`",
    ] {
        assert!(
            found.iter().any(|v| v.contains(needle)),
            "{needle} must be refused: {found:#?}"
        );
    }
    assert_eq!(found.len(), 7, "{found:#?}");
}

#[test]
fn an_unmigrated_row_outside_the_next_slice_or_a_stale_row_is_refused() {
    let ledger = &[TaskSite {
        file: "db.rs",
        function: "close_within",
        op: "join_next",
        count: 1,
        route: TaskRoute::Unmigrated,
    }];
    let src = "async fn close_within(set: &mut S) { let _ = set.join_next().await; }";
    let found = task_violations(&sources(&[("db.rs", src)]), ledger);
    assert!(
        found
            .iter()
            .any(|v| v.contains("ledgered unmigrated outside the files the next slice migrates")),
        "{found:#?}"
    );
    let stale = task_violations(
        &sources(&[("ws_client.rs", "fn start_socket() {}")]),
        SOCKET_ONLY,
    );
    assert!(
        stale.iter().any(|v| v.contains("(stale entry)")),
        "{stale:#?}"
    );
}

#[test]
fn a_carrier_that_drops_a_scope_is_refused() {
    let carried = r"
fn on_behalf_of_caller<F>(task: F) -> F {
    carry_web_session(carry_request_streams(carry_server_request(task)))
}
fn block_on(future: F) {
    let future = on_behalf_of_caller(future);
    crate::threads::spawn_sized(move || future);
}
";
    let found = carrier_gaps(&sources(&[("task.rs", carried)]));
    assert!(found.is_empty(), "{found:#?}");
    let dropped = r"
fn on_behalf_of_caller<F>(task: F) -> F { carry_web_session(carry_request_streams(task)) }
fn block_on(future: F) { crate::threads::spawn_sized(move || future); }
";
    let gaps = carrier_gaps(&sources(&[("task.rs", dropped)]));
    for needle in [
        "never calls `carry_server_request`",
        "`block_on` never carries its future",
    ] {
        assert!(
            gaps.iter().any(|v| v.contains(needle)),
            "{needle} must be refused: {gaps:#?}"
        );
    }
    assert_eq!(gaps.len(), 2, "{gaps:#?}");
}

#[test]
fn a_block_on_carry_out_of_order_or_off_its_future_is_refused() {
    let refused: &[(&str, &str)] = &[
        (
            "fn block_on(future: F) {
                crate::threads::spawn_sized(move || future);
                let future = on_behalf_of_caller(future);
            }",
            "after the `spawn_sized` start",
        ),
        (
            "fn block_on(future: F) {
                let carried = on_behalf_of_caller(future);
                crate::threads::spawn_sized(move || future);
            }",
            "never carries its future",
        ),
        (
            "fn block_on(future: F) {
                let future = on_behalf_of_caller(other);
                crate::threads::spawn_sized(move || future);
            }",
            "never carries its future",
        ),
        (
            "fn block_on(future: F) {
                let future = on_behalf_of_caller(future);
                let future = raw(future);
                crate::threads::spawn_sized(move || future);
            }",
            "rebinds `future`",
        ),
        (
            "fn block_on(future: F) {
                let future = on_behalf_of_caller(future);
                crate::threads::spawn_sized(move || future);
                crate::threads::spawn_sized(move || raw);
            }",
            "calls `spawn_sized` 2 times",
        ),
        (
            "fn block_on(future: F) {
                let future = on_behalf_of_caller(future);
                crate::threads::spawn_sized(move || future);
            }
            fn block_on(future: F) { crate::threads::spawn_sized(move || future); }",
            "2 top-level `block_on` entries",
        ),
    ];
    for (src, needle) in refused {
        let gaps = block_on_carry_gaps(src);
        assert!(
            gaps.len() == 1 && gaps.iter().any(|g| g.contains(needle)),
            "`{needle}` must be refused:\n{src}\n{gaps:#?}"
        );
    }
}

#[test]
fn the_path_naming_file_is_exempt_only_while_it_only_names_paths() {
    let naming = "#[cfg(x)]
const _TOKIO: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::tokio::task::spawn_local::<R>;
    let _: Option<::tokio::task::JoinSet<()>> = None;
};";
    assert!(names_paths_only(naming));
    let found = task_violations(&sources(&[(PATH_NAMING_FILE, naming)]), &[]);
    assert!(found.is_empty(), "{found:#?}");
    for smuggled in [
        "const _T: () = { let _ = ::tokio::spawn(async {}); };",
        "const _T: () = { let _ = ::tokio::spawn; };\nfn start() { tokio::spawn(async {}); }",
        "const T: () = { let _ = ::tokio::spawn; };",
        "const _T: () = { let x = ::tokio::spawn; };",
    ] {
        assert!(!names_paths_only(smuggled), "{smuggled}");
        let found = task_violations(&sources(&[(PATH_NAMING_FILE, smuggled)]), &[]);
        assert!(
            found.iter().any(|v| v.contains("holds an item other than")),
            "{smuggled}: {found:#?}"
        );
    }
}

#[test]
fn every_task_start_and_join_is_the_funnel() {
    let root = e2e_support::manifest_dir!().join("src");
    let found = rust_sources(&root);
    for required in ["threads.rs", "task.rs", "web/mod.rs", "db.rs"] {
        assert!(
            found.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let mut violations = task_violations(&found, TASK_SITES);
    violations.extend(carrier_gaps(&found));
    assert!(
        violations.is_empty(),
        "task funnel scan:\n{}",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------
// Exit-time effects run only as pre-exit stages.
// ---------------------------------------------------------------------------

mod pre_exit_stages {
    //! Every exit-time effect of a driver runs as a `system::pre_exit` stage.
    //!
    //! A driver's teardown or session dump written after its loop is skipped by
    //! `System.exit`, which ends the process from inside the loop. The scan pins
    //! that the drivers reach the recorder only through `record_sink::start`
    //! (whose dump runs as the session-dump stage, at exit or at `finish`) and
    //! that no single-slot exit hook survives beside the stages.

    /// The one `record_sink` entry a driver may name.
    const DRIVER_RECORD_ENTRY: &str = "start";

    /// The record-sink items that write a dump; a driver names none of them.
    const DUMP_ITEMS: &[&str] = &[
        "dump_recorded",
        "render_replay_blob",
        "write_blob",
        "write_typed_log",
        "dump_session",
    ];

    /// The single-slot exit hook the stages replace.
    const RETIRED_EXIT_HOOK: &[&str] =
        &["register_exit_hook", "run_exit_hook", "run_pre_exit_stages"];

    fn runtime_sources() -> Vec<(String, String)> {
        super::rust_sources(&e2e_support::manifest_dir!().join("src"))
    }

    /// Whether `path` is a driver: `tea.rs` or a file under `tui/`.
    fn is_driver(path: &str) -> bool {
        path == "tea.rs" || path.starts_with("tui/")
    }

    /// The identifier that follows each `record_sink::` in `text`.
    fn record_sink_entries(text: &str) -> Vec<&str> {
        text.match_indices("record_sink::")
            .filter_map(|(at, needle)| text.get(at + needle.len()..))
            .map(|rest| {
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                rest.get(..end).unwrap_or_default()
            })
            .collect()
    }

    /// A word occurrence of `item` in `text`, not a prefix of a longer name.
    fn names(text: &str, item: &str) -> bool {
        text.match_indices(item).any(|(at, _)| {
            let before = text.get(..at).and_then(|s| s.chars().next_back());
            let after = text.get(at + item.len()..).and_then(|s| s.chars().next());
            let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            !ident(before) && !ident(after)
        })
    }

    #[test]
    fn dump_has_no_caller_outside_the_stage() {
        let mut offenders = Vec::new();
        let mut drivers = 0usize;
        for (path, text) in runtime_sources() {
            if !is_driver(&path) {
                continue;
            }
            drivers += 1;
            for entry in record_sink_entries(&text) {
                if entry != DRIVER_RECORD_ENTRY {
                    offenders.push(format!("{path}: record_sink::{entry}"));
                }
            }
            for item in DUMP_ITEMS {
                if names(&text, item) {
                    offenders.push(format!("{path}: {item}"));
                }
            }
        }
        assert!(drivers > 1, "the scan found no driver source");
        assert!(
            offenders.is_empty(),
            "a driver reaches a session dump outside its pre-exit stage:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn no_teardown_follows_a_driver_loop() {
        let mut offenders = Vec::new();
        for (path, text) in runtime_sources() {
            for item in RETIRED_EXIT_HOOK {
                if names(&text, item) {
                    offenders.push(format!("{path}: {item}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a single-slot exit hook survives beside the pre-exit stages:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn the_scan_sees_a_record_sink_entry_and_a_named_item() {
        assert_eq!(
            record_sink_entries("a::record_sink::start(x); record_sink::dump_session(y)"),
            ["start", "dump_session"]
        );
        assert!(names("run_exit_hook()", "run_exit_hook"));
        assert!(!names("run_exit_hooks()", "run_exit_hook"));
    }
}

// ---------------------------------------------------------------------------
// A stop signal reaches the process only through its one relay.
// ---------------------------------------------------------------------------

mod stop_signals {
    //! A stop signal ends the process only through the stop relay or the
    //! server's owner.
    //!
    //! The relay (`system::exit_signals`) and the server's owner
    //! (`server::shutdown`) are the only listeners; a third would race them
    //! for the same delivery. The process ends only through
    //! `system::exit_process` and the stop relay's `system::force_exit`, and
    //! every driver entry that registers a pre-exit stage installs the relay,
    //! so a stop signal runs the stages it would otherwise skip.

    /// The files that may name a `tokio::signal` listener, with the count of
    /// code lines naming one: the server owner's listeners (and its test),
    /// and in `system.rs` the spawn probe's listener and the relay's.
    const SIGNAL_LISTENERS: &[(&str, usize)] = &[("server/shutdown.rs", 3), ("system.rs", 4)];

    /// The files that may name `process::exit`, with the count of code lines
    /// naming it: `exit_process` and `force_exit`.
    const PROCESS_EXITS: &[(&str, usize)] = &[("system.rs", 2)];

    /// Each driver entry that registers a pre-exit stage, by file and the
    /// line that opens it, and the relay install it must call.
    const DRIVER_ENTRIES: &[(&str, &str)] = &[
        ("tea.rs", "pub fn console_app<"),
        ("tea.rs", "pub fn worker_app<"),
        ("tui/app.rs", "fn enter_with("),
    ];

    /// The relay install a driver entry calls.
    const INSTALL: &str = "exit_signals::install()";

    /// The gate of the relay and of the widest driver entry (`worker_app`):
    /// the relay compiles wherever a driver entry does.
    const RELAY_GATE: &str = r#"#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]"#;

    /// The items that must carry exactly [`RELAY_GATE`], by file and opener.
    const RELAY_GATED: &[(&str, &str)] = &[
        ("system.rs", "pub(crate) mod exit_signals {"),
        ("tea.rs", "pub fn worker_app<"),
    ];

    fn runtime_sources() -> Vec<(String, String)> {
        super::rust_sources(&e2e_support::manifest_dir!().join("src"))
    }

    /// The count of lines in `text` naming `needle` outside a line comment.
    fn code_lines_naming(text: &str, needle: &str) -> usize {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//") && line.contains(needle))
            .count()
    }

    /// Every file naming `needle` in code, with its count, against `allowed`.
    fn sites_differ(needle: &str, allowed: &[(&str, usize)]) -> Vec<String> {
        let mut found: Vec<(String, usize)> = runtime_sources()
            .into_iter()
            .map(|(path, text)| {
                let count = code_lines_naming(&text, needle);
                (path, count)
            })
            .filter(|(_, count)| *count > 0)
            .collect();
        found.sort();
        let expected: Vec<(String, usize)> = allowed
            .iter()
            .map(|(path, count)| ((*path).to_owned(), *count))
            .collect();
        if found == expected {
            Vec::new()
        } else {
            vec![format!("expected {expected:?}, found {found:?}")]
        }
    }

    /// The item `opener` begins in `text`, up to the closing brace at the
    /// opener's own indentation.
    fn item_body<'t>(text: &'t str, opener: &str) -> Option<&'t str> {
        let at = text.find(opener)?;
        let line_start = text.get(..at)?.rfind('\n').map_or(0, |nl| nl + 1);
        let indent = text.get(line_start..at)?;
        let close = format!("\n{indent}}}\n");
        let rest = text.get(at..)?;
        let end = rest.find(&close)?;
        rest.get(..end)
    }

    #[test]
    fn the_stop_relay_is_the_only_signal_listener_outside_the_server() {
        let differ = sites_differ("tokio::signal", SIGNAL_LISTENERS);
        assert!(
            differ.is_empty(),
            "a stop-signal listener sits outside the relay and the server owner:\n{}",
            differ.join("\n")
        );
    }

    #[test]
    fn std_process_exit_has_exactly_two_sites() {
        let differ = sites_differ("process::exit", PROCESS_EXITS);
        assert!(
            differ.is_empty(),
            "the process ends outside `exit_process` and `force_exit`:\n{}",
            differ.join("\n")
        );
    }

    /// The line directly above the line `opener` begins on, trimmed.
    fn line_above<'t>(text: &'t str, opener: &str) -> Option<&'t str> {
        let at = text.find(opener)?;
        let line_start = text.get(..at)?.rfind('\n')?;
        text.get(..line_start)?.lines().next_back().map(str::trim)
    }

    /// Whether `body` names `needle` on exactly one code line, and that line
    /// stands under no `#[cfg` attribute of its own.
    fn names_once_unconditionally(body: &str, needle: &str) -> bool {
        code_lines_naming(body, needle) == 1
            && line_above(body, needle).is_some_and(|above| !above.starts_with("#[cfg"))
    }

    #[test]
    fn every_driver_entry_installs_the_relay() {
        let sources = runtime_sources();
        let mut missing = Vec::new();
        for (file, opener) in DRIVER_ENTRIES {
            let installs = sources
                .iter()
                .find(|(path, _)| path == file)
                .and_then(|(_, text)| item_body(text, opener))
                .is_some_and(|body| names_once_unconditionally(body, INSTALL));
            if !installs {
                missing.push(format!("{file}: {opener}"));
            }
        }
        assert!(
            missing.is_empty(),
            "a driver entry does not install the stop relay exactly once, unconditionally:\n{}",
            missing.join("\n")
        );
    }

    #[test]
    fn the_relay_compiles_wherever_a_driver_entry_does() {
        let sources = runtime_sources();
        let mut differ = Vec::new();
        for (file, opener) in RELAY_GATED {
            let gate = sources
                .iter()
                .find(|(path, _)| path == file)
                .and_then(|(_, text)| line_above(text, opener));
            if gate != Some(RELAY_GATE) {
                differ.push(format!("{file}: {opener} is gated {gate:?}"));
            }
        }
        assert!(
            differ.is_empty(),
            "the relay and the widest driver entry must share {RELAY_GATE}:\n{}",
            differ.join("\n")
        );
    }

    #[test]
    fn the_scan_reads_code_lines_and_item_bodies() {
        assert_eq!(
            code_lines_naming(
                "// process::exit\nstd::process::exit(1);\n",
                "process::exit"
            ),
            1
        );
        let text =
            "impl T {\n    fn enter_with() {\n        install();\n    }\n    fn other() {}\n}\n";
        assert_eq!(
            item_body(text, "fn enter_with("),
            Some("fn enter_with() {\n        install();")
        );
        assert_eq!(item_body(text, "fn absent("), None);
        let gated = "fn entry() {\n    #[cfg(feature = \"tui\")]\n    let _ = install();\n}\n";
        assert!(!names_once_unconditionally(gated, "install()"));
        let plain = "fn entry() {\n    // installs\n    let _ = install();\n}\n";
        assert!(names_once_unconditionally(plain, "install()"));
        assert_eq!(
            line_above("#[cfg(x)]\npub mod relay {\n}\n", "pub mod relay {"),
            Some("#[cfg(x)]")
        );
        assert_eq!(line_above("pub mod relay {\n}\n", "pub mod relay {"), None);
    }
}

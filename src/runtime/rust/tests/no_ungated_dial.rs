//! Dial-gate scan: every raw network dial in the runtime must route through
//! its typed SSRF gate.
//!
//! Every `.rs` file under `src/` is scanned under every rule. The rule is
//! structural, never proximity-based. A sqlx dial (`connect`, `connect_with`,
//! `connect_lazy`, `connect_lazy_with`, in any method, path, or reference form)
//! or `*PoolOptions` opener is admitted only as `VettedPool`'s own associated
//! `connect`, reached as `VettedPool`, `crate::db::VettedPool`, or
//! `super::db::VettedPool`; `db.rs` holds exactly one raw dial, inside the body
//! of `VettedPool::connect`, whose argument is the one binding that body takes
//! from the driver-typed `DB::gated_connect_options`. The only other raw dials
//! are the named entries of [`ALLOWED_DIALS`], each matching exactly one dial.
//! An SMTP transport is admitted only when its host argument is
//! `<binding>.dial_host(…)`, a method only `VettedDial` in `ssrf.rs` may
//! define. Renaming or redefining a gate or dial name is itself a violation,
//! since it would let a raw dial wear the gate's name.
//!
//! Every source is parsed with `syn`, so the scan reads the same syntax tree
//! rustc does: comments and string literals are never code, and a
//! `#[cfg(test)]` attribute removes exactly the node it is attached to (an
//! item, field, variant, match arm, statement, or expression) and nothing
//! after it. A node whose `cfg` is not proven test-only is scanned, so an
//! unrecognised shape can only turn the scan red, never vacuously green. A
//! macro body is scanned as the expressions or statements it parses as, or,
//! when it parses as neither, token by token, where every dial-named
//! identifier counts as an ungated dial; inside a macro body no `#[cfg(test)]`
//! is honoured, since the macro decides what its attributes mean. Syntax `syn`
//! keeps only as tokens (a verbatim item or expression) is scanned token by
//! token too.

use proc_macro2::{TokenStream, TokenTree};
use std::path::{Path, PathBuf};
use syn::ext::IdentExt;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Block, Expr, ExprAssign, ExprCall, ExprMethodCall, ExprPath, Field, FieldValue,
    ForeignItem, ForeignItemFn, Ident, ImplItem, ImplItemFn, Item, ItemFn, ItemImpl, ItemUse,
    Local, Macro, Meta, Pat, PatIdent, Stmt, Token, TraitItem, TraitItemFn, Type, TypeParam,
    UseTree, Variant,
};

// ---------------------------------------------------------------------------
// Names the scan classifies.
// ---------------------------------------------------------------------------

/// sqlx functions that open a connection or a pool.
const DIAL_FNS: &[&str] = &[
    "connect",
    "connect_with",
    "connect_lazy",
    "connect_lazy_with",
];

/// The one type whose associated `connect` routes every dial through the gate.
const GATED_OWNER: &str = "VettedPool";

/// The module that defines [`GATED_OWNER`].
const GATED_OWNER_MODULE: &str = "db";

/// The file that defines [`GATED_OWNER`].
const GATED_OWNER_FILE: &str = "db.rs";

/// The module paths [`GATED_OWNER`] may be reached through, besides its bare name.
const GATED_OWNER_PATHS: [[&str; 2]; 2] =
    [["crate", GATED_OWNER_MODULE], ["super", GATED_OWNER_MODULE]];

/// The gate function `VettedPool::connect` takes its options from.
const GATE_OPTIONS_FN: &str = "gated_connect_options";

/// The driver type parameter `VettedPool::connect` calls the gate through.
const GATE_DRIVER_PARAM: &str = "DB";

/// lettre functions that build an SMTP transport dialing their host argument.
const SMTP_TRANSPORT_FNS: &[&str] = &["builder_dangerous", "relay", "starttls_relay", "from_url"];

/// The `VettedDial` method that yields the vetted dial host.
const VETTED_HOST_FN: &str = "dial_host";

/// The type whose method [`VETTED_HOST_FN`] is.
const VETTED_HOST_OWNER: &str = "VettedDial";

/// The file that defines [`VETTED_HOST_OWNER`].
const VETTED_HOST_FILE: &str = "ssrf.rs";

/// Keywords after which an identifier is the name being defined.
const DEFINING_KEYWORDS: [&str; 9] = [
    "fn", "struct", "enum", "union", "type", "trait", "mod", "static", "const",
];

/// A raw dial outside `db.rs` admitted by name, because it opens no
/// caller-supplied network target.
struct AllowedDial {
    /// The source file, relative to `src/`.
    file: &'static str,
    /// The free function whose body holds the dial.
    func: &'static str,
    /// The dial's path, as written.
    dial: &'static str,
    /// Why the dial needs no gate.
    why: &'static str,
}

impl AllowedDial {
    /// Whether `dial` is this entry's.
    fn admits(&self, dial: &Dial) -> bool {
        dial.path == self.dial
            && dial.within.impl_of.is_none()
            && dial.within.func.as_deref() == Some(self.func)
    }
}

/// Every raw dial admitted outside `db.rs`; each must match exactly one dial.
const ALLOWED_DIALS: [AllowedDial; 5] = [
    AllowedDial {
        file: "web/hub.rs",
        func: "open_spill",
        dial: "SqlitePool::connect_with",
        why: "opens the console's local SQLite spill file from a filesystem path, not a URL",
    },
    AllowedDial {
        file: "telemetry_spill.rs",
        func: "enable_from_env",
        dial: "SqlitePool::connect",
        why: "opens the local SQLite spill file the runtime's own environment names",
    },
    AllowedDial {
        file: "ws_client.rs",
        func: "do_connect",
        dial: "tokio::net::TcpStream::connect",
        why: "a TCP dial of the address `VettedDial::Pinned` proved, not a sqlx dial",
    },
    AllowedDial {
        file: "ssrf.rs",
        func: "dial_relay_target",
        dial: "tokio::net::TcpStream::connect",
        why: "the pinned relay's TCP dial of a `VettedAddr`, which only `VettedDial::Pinned` can mint, not a sqlx dial",
    },
    AllowedDial {
        file: "web/console_proxy.rs",
        func: "wait_ready",
        dial: "tokio::net::TcpStream::connect",
        why: "a loopback readiness probe of the child this process spawned, not a sqlx dial",
    },
];

/// Whether `name` is a sqlx pool-options builder.
fn is_pool_options(name: &str) -> bool {
    name.ends_with("PoolOptions")
}

/// Whether renaming `name` in a `use` would hide a dial or a gate from the scan.
fn is_guarded_name(name: &str) -> bool {
    DIAL_FNS.contains(&name)
        || SMTP_TRANSPORT_FNS.contains(&name)
        || is_pool_options(name)
        || [GATED_OWNER, GATE_OPTIONS_FN, VETTED_HOST_FN, "VettedDial"].contains(&name)
}

/// `id` as written, without any `r#` prefix.
fn name_of(id: &Ident) -> String {
    id.unraw().to_string()
}

// ---------------------------------------------------------------------------
// `#[cfg(...)]` classification.
// ---------------------------------------------------------------------------

/// Whether `predicate` can hold only when `test` is set.
///
/// `all(…)` needs every member, so one test-only member suffices; `any(…)` is
/// test-only only when every member is. `not(…)`, `feature = "test"`, and any
/// other shape are not proven test-only, so the node they gate is scanned.
fn test_only(predicate: &Meta) -> bool {
    match predicate {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let members = list
                .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                .ok();
            if list.path.is_ident("all") {
                members.is_some_and(|m| m.iter().any(test_only))
            } else if list.path.is_ident("any") {
                members.is_some_and(|m| !m.is_empty() && m.iter().all(test_only))
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Whether one of `attrs` is a `#[cfg(…)]` that holds only under `test`.
fn cfg_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && attr.parse_args::<Meta>().is_ok_and(|p| test_only(&p))
    })
}

/// The outer attributes of `item`.
fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// The name `item` defines, when it defines one.
fn item_name(item: &Item) -> Option<String> {
    match item {
        Item::Const(i) => Some(name_of(&i.ident)),
        Item::Enum(i) => Some(name_of(&i.ident)),
        Item::ExternCrate(i) => Some(name_of(
            i.rename.as_ref().map_or(&i.ident, |(_, rename)| rename),
        )),
        Item::Fn(i) => Some(name_of(&i.sig.ident)),
        Item::Macro(i) => i.ident.as_ref().map(name_of),
        Item::Mod(i) => Some(name_of(&i.ident)),
        Item::Static(i) => Some(name_of(&i.ident)),
        Item::Struct(i) => Some(name_of(&i.ident)),
        Item::Trait(i) => Some(name_of(&i.ident)),
        Item::TraitAlias(i) => Some(name_of(&i.ident)),
        Item::Type(i) => Some(name_of(&i.ident)),
        Item::Union(i) => Some(name_of(&i.ident)),
        _ => None,
    }
}

/// The outer attributes of `item`.
fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

/// The outer attributes of `item`.
fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => &[],
    }
}

/// The outer attributes of `expr`, for every expression kind that can carry one.
///
/// An expression kind missing here keeps its attributes unread, so a
/// `#[cfg(test)]` on it is not honoured and the expression stays scanned.
fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// The syntax-tree walk.
// ---------------------------------------------------------------------------

/// Where a node sits: its enclosing `impl` (type and trait) and function.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Scope {
    impl_of: Option<String>,
    of_trait: Option<String>,
    func: Option<String>,
}

impl Scope {
    /// The body of the inherent `VettedPool::connect`, the one place a raw dial may appear.
    fn gate() -> Self {
        Self {
            impl_of: Some(GATED_OWNER.to_owned()),
            of_trait: None,
            func: Some("connect".to_owned()),
        }
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.impl_of, &self.of_trait) {
            (Some(ty), Some(tr)) => write!(f, "impl {tr} for {ty} ")?,
            (Some(ty), None) => write!(f, "impl {ty} ")?,
            (None, _) => {}
        }
        match &self.func {
            Some(func) => write!(f, "fn {func}"),
            None => f.write_str("item scope"),
        }
    }
}

/// What a [`Dial`] opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DialKind {
    /// A call to, or a reference to, one of [`DIAL_FNS`].
    Sqlx,
    /// A sqlx `*PoolOptions` builder, which opens a pool.
    PoolOptions,
}

/// One dial or pool opener in production code.
#[derive(Clone, Debug)]
struct Dial {
    name: String,
    /// The path the dial is reached through, as written (`.name` for a method).
    path: String,
    kind: DialKind,
    /// A `VettedPool::connect` call, which routes through the gate.
    gated: bool,
    /// The first argument, when it is a bare local name.
    arg: Option<String>,
    within: Scope,
}

/// One SMTP transport constructor in production code.
#[derive(Clone, Debug)]
struct Transport {
    name: String,
    /// Its first argument is `<binding>.dial_host(…)`.
    vetted: bool,
    within: Scope,
}

/// Everything the walk records about one source file.
#[derive(Default)]
struct Scan {
    scope: Scope,
    /// How many macro bodies enclose the node being walked.
    macro_depth: usize,
    /// Every function body walked.
    fns: Vec<Scope>,
    dials: Vec<Dial>,
    transports: Vec<Transport>,
    /// `struct VettedPool` definitions.
    gate_structs: usize,
    /// Renames or definitions that could make a raw dial wear a gate's name.
    forgeries: Vec<String>,
    /// Every `fn dial_host` definition, with its scope.
    vetted_host_defs: Vec<Scope>,
    /// Every name a pattern binds, with its scope.
    bindings: Vec<(Scope, String)>,
    /// `let <name> = DB::gated_connect_options(…)…;` bindings, with their scope.
    gated_lets: Vec<(Scope, String)>,
    /// Every `<name> = …` assignment, with its scope.
    assigned: Vec<(Scope, String)>,
}

/// The last segment of `ty`'s path, when it is a path type.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(tp) => tp.path.segments.last().map(|s| name_of(&s.ident)),
        _ => None,
    }
}

/// The bare local name `expr` is, when it is one.
fn local_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(p) if p.qself.is_none() => p.path.get_ident().map(name_of),
        _ => None,
    }
}

/// Whether `expr` is `DB::gated_connect_options(…)`, possibly awaited and `?`-ed.
fn is_gate_options_call(expr: &Expr) -> bool {
    match expr {
        Expr::Try(e) => is_gate_options_call(&e.expr),
        Expr::Await(e) => is_gate_options_call(&e.base),
        Expr::Paren(e) => is_gate_options_call(&e.expr),
        Expr::Call(call) => match &*call.func {
            Expr::Path(p) if p.qself.is_none() => {
                let names: Vec<String> =
                    p.path.segments.iter().map(|s| name_of(&s.ident)).collect();
                names == [GATE_DRIVER_PARAM, GATE_OPTIONS_FN]
            }
            _ => false,
        },
        _ => false,
    }
}

/// Whether `module` is a path [`GATED_OWNER`] may be reached through: none,
/// or one of [`GATED_OWNER_PATHS`].
fn is_gated_owner_module(module: &[String]) -> bool {
    module.is_empty() || is_gated_owner_path(module)
}

/// Whether `module` is exactly one of [`GATED_OWNER_PATHS`].
fn is_gated_owner_path(module: &[String]) -> bool {
    GATED_OWNER_PATHS
        .iter()
        .any(|path| module.len() == path.len() && module.iter().zip(path).all(|(m, p)| m == p))
}

/// Whether `expr` is `<binding>.dial_host(…)`.
fn is_vetted_host(expr: &Expr) -> bool {
    match expr {
        Expr::MethodCall(m) => {
            name_of(&m.method) == VETTED_HOST_FN && local_name(&m.receiver).is_some()
        }
        _ => false,
    }
}

impl Scan {
    /// Whether `attrs` remove their node from the build.
    ///
    /// Inside a macro body no attribute is honoured: the macro, not rustc,
    /// decides what it means.
    fn prunes(&self, attrs: &[Attribute]) -> bool {
        self.macro_depth == 0 && cfg_test_only(attrs)
    }

    /// Records `name` when it defines [`VETTED_HOST_FN`].
    fn record_fn_def(&mut self, name: &str) {
        if name == VETTED_HOST_FN {
            self.vetted_host_defs.push(self.scope.clone());
        }
    }

    /// Walks `body` with `scope` as the enclosing scope, then restores the outer one.
    fn within(&mut self, scope: Scope, body: impl FnOnce(&mut Self)) {
        let outer = std::mem::replace(&mut self.scope, scope);
        body(self);
        self.scope = outer;
    }

    fn record_dial(
        &mut self,
        name: String,
        path: String,
        kind: DialKind,
        gated: bool,
        arg: Option<String>,
    ) {
        self.dials.push(Dial {
            name,
            path,
            kind,
            gated,
            arg,
            within: self.scope.clone(),
        });
    }

    fn record_transport(&mut self, name: String, vetted: bool) {
        self.transports.push(Transport {
            name,
            vetted,
            within: self.scope.clone(),
        });
    }

    /// Records the dial `path` names, if any, and whether it is gated.
    ///
    /// A `VettedPool::connect` path is gated only without a qualified self
    /// type or a leading `::`, and only as `VettedPool::connect` or through
    /// one of [`GATED_OWNER_PATHS`].
    fn record_path_dial(&mut self, path: &ExprPath, arg: Option<String>) -> bool {
        let names: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|s| name_of(&s.ident))
            .collect();
        let Some(last) = names.last() else {
            return false;
        };
        let written = names.join("::");
        if DIAL_FNS.contains(&last.as_str()) {
            let owner_at = names.len().checked_sub(2);
            let owner = owner_at.and_then(|i| names.get(i));
            let module = owner_at.and_then(|i| names.get(..i));
            let gated = path.qself.is_none()
                && path.path.leading_colon.is_none()
                && owner.is_some_and(|o| o == GATED_OWNER)
                && module.is_some_and(is_gated_owner_module);
            self.record_dial(last.clone(), written, DialKind::Sqlx, gated, arg);
            return true;
        }
        if let Some(opener) = names.iter().find(|n| is_pool_options(n)) {
            self.record_dial(opener.clone(), written, DialKind::PoolOptions, false, None);
            return true;
        }
        false
    }

    /// Records every dial- or transport-named identifier in `tokens` as
    /// ungated, and every gate name a keyword defines as a forgery or a
    /// [`VETTED_HOST_FN`] definition.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut defining: Option<String> = None;
        for tree in tokens {
            let mut keyword = None;
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(id) => {
                    let name = name_of(&id);
                    if let Some(kw) = defining.as_deref() {
                        if kw == "fn" {
                            self.record_fn_def(&name);
                        }
                        if name == GATED_OWNER {
                            self.forgeries.push(format!(
                                "{}: a macro body defines `{kw} {GATED_OWNER}`",
                                self.scope
                            ));
                        }
                    }
                    if DIAL_FNS.contains(&name.as_str()) {
                        self.record_dial(name.clone(), name, DialKind::Sqlx, false, None);
                    } else if is_pool_options(&name) {
                        self.record_dial(name.clone(), name, DialKind::PoolOptions, false, None);
                    } else if SMTP_TRANSPORT_FNS.contains(&name.as_str()) {
                        self.record_transport(name, false);
                    } else if DEFINING_KEYWORDS.contains(&name.as_str()) {
                        keyword = Some(name);
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
            defining = keyword;
        }
    }

    /// Records a forgery when `tree` renames a guarded name or imports
    /// `VettedPool` through any path but [`GATED_OWNER_PATHS`].
    fn scan_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(p) => {
                prefix.push(name_of(&p.ident));
                self.scan_use(&p.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(n) => {
                if name_of(&n.ident) == GATED_OWNER && !is_gated_owner_path(prefix) {
                    self.forgeries.push(format!(
                        "{}: imports `{GATED_OWNER}` from `{}`, not `crate::{GATED_OWNER_MODULE}` \
                         or `super::{GATED_OWNER_MODULE}`",
                        self.scope,
                        prefix.join("::")
                    ));
                }
            }
            UseTree::Rename(r) => {
                let (from, to) = (name_of(&r.ident), name_of(&r.rename));
                if is_guarded_name(&from) || is_guarded_name(&to) {
                    self.forgeries
                        .push(format!("{}: renames `{from}` as `{to}`", self.scope));
                }
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.scan_use(item, prefix);
                }
            }
            UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        if self.prunes(item_attrs(item)) {
            return;
        }
        if let Item::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        if item_name(item).is_some_and(|n| n == GATED_OWNER) {
            if matches!(item, Item::Struct(_)) {
                self.gate_structs += 1;
            } else {
                self.forgeries.push(format!(
                    "{}: defines a non-struct `{GATED_OWNER}`",
                    self.scope
                ));
            }
        }
        visit::visit_item(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        // A leading `::` names an external crate, never this one's `db`.
        let mut prefix = item
            .leading_colon
            .map_or_else(Vec::new, |_| vec![String::new()]);
        self.scan_use(&item.tree, &mut prefix);
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let scope = Scope {
            func: Some(name_of(&item.sig.ident)),
            ..Scope::default()
        };
        self.fns.push(scope.clone());
        self.record_fn_def(&name_of(&item.sig.ident));
        self.within(scope, |s| visit::visit_item_fn(s, item));
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let scope = Scope {
            impl_of: type_name(&item.self_ty),
            of_trait: item
                .trait_
                .as_ref()
                .and_then(|(_, path, _)| path.segments.last())
                .map(|s| name_of(&s.ident)),
            func: None,
        };
        self.within(scope, |s| visit::visit_item_impl(s, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if self.prunes(impl_item_attrs(item)) {
            return;
        }
        if let ImplItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        self.record_fn_def(&name_of(&item.sig.ident));
        let scope = Scope {
            func: Some(name_of(&item.sig.ident)),
            ..self.scope.clone()
        };
        self.fns.push(scope.clone());
        self.within(scope, |s| visit::visit_impl_item_fn(s, item));
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if self.prunes(trait_item_attrs(item)) {
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

    fn visit_foreign_item_fn(&mut self, item: &'ast ForeignItemFn) {
        self.record_fn_def(&name_of(&item.sig.ident));
        visit::visit_foreign_item_fn(self, item);
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        self.record_fn_def(&name_of(&item.sig.ident));
        let scope = Scope {
            func: Some(name_of(&item.sig.ident)),
            ..self.scope.clone()
        };
        self.fns.push(scope.clone());
        self.within(scope, |s| visit::visit_trait_item_fn(s, item));
    }

    fn visit_type_param(&mut self, param: &'ast TypeParam) {
        if name_of(&param.ident) == GATED_OWNER {
            self.forgeries.push(format!(
                "{}: declares a type parameter named `{GATED_OWNER}`",
                self.scope
            ));
        }
        visit::visit_type_param(self, param);
    }

    fn visit_field(&mut self, field: &'ast Field) {
        if !self.prunes(&field.attrs) {
            visit::visit_field(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast Variant) {
        if !self.prunes(&variant.attrs) {
            visit::visit_variant(self, variant);
        }
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !self.prunes(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast FieldValue) {
        if !self.prunes(&field.attrs) {
            visit::visit_field_value(self, field);
        }
    }

    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        let attrs: &[Attribute] = match stmt {
            Stmt::Local(local) => &local.attrs,
            Stmt::Macro(mac) => &mac.attrs,
            _ => &[],
        };
        if !self.prunes(attrs) {
            visit::visit_stmt(self, stmt);
        }
    }

    fn visit_local(&mut self, local: &'ast Local) {
        let bound = match &local.pat {
            Pat::Ident(p) if p.by_ref.is_none() && p.mutability.is_none() && p.subpat.is_none() => {
                Some(name_of(&p.ident))
            }
            _ => None,
        };
        if let (Some(name), Some(init)) = (bound, &local.init)
            && init.diverge.is_none()
            && is_gate_options_call(&init.expr)
        {
            self.gated_lets.push((self.scope.clone(), name));
        }
        visit::visit_local(self, local);
    }

    fn visit_pat_ident(&mut self, pat: &'ast PatIdent) {
        self.bindings
            .push((self.scope.clone(), name_of(&pat.ident)));
        visit::visit_pat_ident(self, pat);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if self.prunes(expr_attrs(expr)) {
            return;
        }
        if let Expr::Verbatim(tokens) = expr {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_expr(self, expr);
    }

    fn visit_pat(&mut self, pat: &'ast Pat) {
        if let Pat::Verbatim(tokens) = pat {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_pat(self, pat);
    }

    fn visit_type(&mut self, ty: &'ast Type) {
        if let Type::Verbatim(tokens) = ty {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_type(self, ty);
    }

    fn visit_expr_assign(&mut self, assign: &'ast ExprAssign) {
        if let Some(name) = local_name(&assign.left) {
            self.assigned.push((self.scope.clone(), name));
        }
        visit::visit_expr_assign(self, assign);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = &*call.func {
            let arg = call.args.first().and_then(local_name);
            if self.record_path_dial(func, arg) {
                for arg in &call.args {
                    self.visit_expr(arg);
                }
                return;
            }
            if let Some(last) = func.path.segments.last()
                && SMTP_TRANSPORT_FNS.contains(&name_of(&last.ident).as_str())
            {
                let vetted = call.args.first().is_some_and(is_vetted_host);
                self.record_transport(name_of(&last.ident), vetted);
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = name_of(&call.method);
        if DIAL_FNS.contains(&method.as_str()) {
            let arg = call.args.first().and_then(local_name);
            self.record_dial(
                method.clone(),
                format!(".{method}"),
                DialKind::Sqlx,
                false,
                arg,
            );
        } else if SMTP_TRANSPORT_FNS.contains(&method.as_str()) {
            let vetted = call.args.first().is_some_and(is_vetted_host);
            self.record_transport(method, vetted);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        self.record_path_dial(path, None);
        visit::visit_expr_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.macro_depth = self.macro_depth.saturating_add(1);
        if let Ok(exprs) = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            for expr in &exprs {
                self.visit_expr(expr);
            }
        } else if let Ok(stmts) = mac.parse_body_with(Block::parse_within) {
            for stmt in &stmts {
                self.visit_stmt(stmt);
            }
        } else {
            self.scan_tokens(mac.tokens.clone());
        }
        self.macro_depth = self.macro_depth.saturating_sub(1);
    }
}

/// The production syntax of `src`, walked; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Scan {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its dials cannot be proven gated: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan
}

// ---------------------------------------------------------------------------
// The rules.
// ---------------------------------------------------------------------------

/// Every raw sqlx dial or pool opener in `scan` that is neither gated nor an
/// entry of `allowed`, and every entry of `allowed` for `name` that does not
/// match exactly one dial.
fn raw_dial_violations(name: &str, scan: &Scan, allowed: &[AllowedDial]) -> Vec<String> {
    let entries: Vec<&AllowedDial> = allowed.iter().filter(|a| a.file == name).collect();
    let mut violations: Vec<String> = scan
        .dials
        .iter()
        .filter(|d| !d.gated && !entries.iter().any(|a| a.admits(d)))
        .map(|d| format!("{name}: {}: raw dial `{}`", d.within, d.name))
        .collect();
    for entry in entries {
        let matched = scan
            .dials
            .iter()
            .filter(|d| !d.gated && entry.admits(d))
            .count();
        if matched != 1 {
            violations.push(format!(
                "{name}: allowed dial `{}` in fn {} ({}) matches {matched} dials; exactly one \
                 is admitted",
                entry.dial, entry.func, entry.why
            ));
        }
    }
    if scan.gate_structs > 0 {
        violations.push(format!(
            "{name}: defines `struct {GATED_OWNER}`, which only `{GATED_OWNER_FILE}` may"
        ));
    }
    violations
}

/// Every gate forgery in `scan`.
///
/// Besides renames and redefinitions of a gate name, a `dial_host` defined
/// anywhere but inherently on `VettedDial` in `ssrf.rs` is a forgery, and
/// `ssrf.rs` defines exactly one.
fn forgery_violations(name: &str, scan: &Scan) -> Vec<String> {
    let mut violations: Vec<String> = scan
        .forgeries
        .iter()
        .map(|f| format!("{name}: {f}"))
        .collect();
    let home = |def: &Scope| {
        name == VETTED_HOST_FILE
            && def.impl_of.as_deref() == Some(VETTED_HOST_OWNER)
            && def.of_trait.is_none()
    };
    for def in scan.vetted_host_defs.iter().filter(|d| !home(d)) {
        violations.push(format!(
            "{name}: {def}: defines `{VETTED_HOST_FN}`, which only `{VETTED_HOST_OWNER}` in \
             `{VETTED_HOST_FILE}` may"
        ));
    }
    let at_home = scan.vetted_host_defs.iter().filter(|d| home(d)).count();
    if name == VETTED_HOST_FILE && at_home != 1 {
        violations.push(format!(
            "{name}: {at_home} `{VETTED_HOST_OWNER}::{VETTED_HOST_FN}` definitions; exactly one \
             is the gate"
        ));
    }
    violations
}

/// Every raw sqlx dial or pool opener and every gate forgery in `src`.
///
/// Only a gated `VettedPool::connect` call is admitted; every other dial, in
/// any syntactic form, is a violation naming its enclosing scope.
fn caller_url_violations(name: &str, src: &str) -> Vec<String> {
    let scan = scan(name, src);
    let mut violations = raw_dial_violations(name, &scan, &[]);
    violations.extend(forgery_violations(name, &scan));
    violations
}

/// Why the one dial inside `VettedPool::connect` is not proven gated, if it is not.
///
/// Its argument must be a name bound exactly once in that body, by a `let`
/// taking `DB::gated_connect_options(…)`, and never reassigned.
fn gate_argument_violation(scan: &Scan, dial: &Dial) -> Option<String> {
    let gate = Scope::gate();
    let in_gate = |entries: &[(Scope, String)], arg: &str| {
        entries
            .iter()
            .filter(|(scope, bound)| *scope == gate && bound == arg)
            .count()
    };
    let proven = dial.arg.as_deref().is_some_and(|arg| {
        in_gate(&scan.bindings, arg) == 1
            && in_gate(&scan.gated_lets, arg) == 1
            && in_gate(&scan.assigned, arg) == 0
    });
    (!proven).then(|| {
        format!(
            "VettedPool::connect dials `{}({})`, which does not take its options from \
             {GATE_DRIVER_PARAM}::{GATE_OPTIONS_FN}",
            dial.name,
            dial.arg.as_deref().unwrap_or("…")
        )
    })
}

/// Every raw dial in `scan` that bypasses the typed gate of `db.rs`.
///
/// Exactly one raw dial is admitted, inside the inherent `VettedPool::connect`,
/// and only when its argument is that body's binding of
/// `DB::gated_connect_options(…)`: the driver type, not any text near the
/// call, decides which gate runs.
fn db_gate_violations(name: &str, scan: &Scan) -> Vec<String> {
    let gate = Scope::gate();
    let mut violations = Vec::new();
    let bodies = scan.fns.iter().filter(|f| **f == gate).count();
    if bodies != 1 {
        violations.push(format!(
            "{name}: {bodies} VettedPool::connect bodies found; exactly one is the gate"
        ));
    }
    let admitted: Vec<&Dial> = scan
        .dials
        .iter()
        .filter(|d| !d.gated && d.kind == DialKind::Sqlx && d.within == gate)
        .collect();
    match admitted.as_slice() {
        [dial] => {
            violations.extend(gate_argument_violation(scan, dial).map(|v| format!("{name}: {v}")))
        }
        _ if bodies == 1 => violations.push(format!(
            "{name}: VettedPool::connect holds {} raw dials; exactly one is admitted",
            admitted.len()
        )),
        _ => {}
    }
    for dial in scan.dials.iter().filter(|d| !d.gated && d.within != gate) {
        violations.push(format!(
            "{name}: {}: raw dial `{}` outside VettedPool::connect",
            dial.within, dial.name
        ));
    }
    if scan.gate_structs > 1 {
        violations.push(format!(
            "{name}: {} `struct {GATED_OWNER}` definitions",
            scan.gate_structs
        ));
    }
    violations
}

/// Every raw dial in `src`'s production code that bypasses the typed gate,
/// and every gate forgery.
fn db_dials_bypassing_the_gate(name: &str, src: &str) -> Vec<String> {
    let scan = scan(name, src);
    let mut violations = db_gate_violations(name, &scan);
    violations.extend(forgery_violations(name, &scan));
    violations
}

/// Every SMTP transport in `scan` built from a host that did not pass the gate.
///
/// A transport is gated only when its first argument is `<binding>.dial_host(…)`:
/// `dial_host` exists only on `VettedDial`, whose sole constructor runs the SSRF
/// gate, so the argument's type proves the host was vetted.
fn transport_violations(name: &str, scan: &Scan) -> Vec<String> {
    scan.transports
        .iter()
        .filter(|t| !t.vetted)
        .map(|t| format!("{name}: {}: `{}` dials an unvetted host", t.within, t.name))
        .collect()
}

/// Every SMTP transport in `src` built from an unvetted host, and every gate forgery.
fn ungated_smtp_transports(name: &str, src: &str) -> Vec<String> {
    let scan = scan(name, src);
    let mut violations = transport_violations(name, &scan);
    violations.extend(forgery_violations(name, &scan));
    violations
}

/// Every violation of every rule in the source file `name`, relative to `src/`.
///
/// `db.rs` holds the gate, so its raw dials are held to the gate rule; every
/// other file admits only gated dials and [`ALLOWED_DIALS`].
fn tree_violations(name: &str, src: &str) -> Vec<String> {
    let scan = scan(name, src);
    let mut violations = if name == GATED_OWNER_FILE {
        db_gate_violations(name, &scan)
    } else {
        raw_dial_violations(name, &scan, &ALLOWED_DIALS)
    };
    violations.extend(transport_violations(name, &scan));
    violations.extend(forgery_violations(name, &scan));
    violations
}

/// Asserts `violations` has `count` entries, each containing `needle`.
fn assert_violations(violations: &[String], count: usize, needle: &str) {
    assert_eq!(violations.len(), count, "{violations:#?}");
    assert!(
        violations.iter().all(|v| v.contains(needle)),
        "every violation must name `{needle}`: {violations:#?}"
    );
}

// ---------------------------------------------------------------------------
// Refusal tests: `#[cfg(test)]` removes exactly its own node.
// ---------------------------------------------------------------------------

#[test]
fn cfg_test_module_is_dropped_and_production_after_it_is_scanned() {
    let fixture = r#"
#[cfg(test)]
mod t {
    fn helper() {
        let _ = PgPool::connect("unguarded-test-only");
    }
}

fn production() {
    PgPool::connect("unguarded-production");
}
"#;
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

#[test]
fn cfg_test_item_on_the_same_line_is_dropped_alone() {
    let fixture = r#"
fn before() { PgPool::connect(before_url); }
#[cfg(test)] fn only_in_tests() { let s = "{ not a real brace }"; PgPool::connect(t); }
fn after() { PgPool::connect(after_url); }
"#;
    let violations = caller_url_violations("fixture.rs", fixture);
    assert_eq!(violations.len(), 2, "{violations:#?}");
    assert!(
        violations.iter().any(|v| v.contains("fn before")),
        "{violations:#?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("fn after")),
        "{violations:#?}"
    );
}

/// A `#[cfg(test)]` struct field ends at its own `,`; the next item is scanned.
#[test]
fn cfg_test_struct_field_does_not_hide_the_next_item() {
    let fixture = r"
struct Probe {
    #[cfg(test)]
    seen: u8,
}
fn production() {
    let _ = PgPool::connect(url);
}
";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

/// A `#[cfg(test)]` enum variant ends at its own `,`; the next item is scanned.
#[test]
fn cfg_test_enum_variant_does_not_hide_the_next_item() {
    let fixture = r"
enum Mode {
    Live,
    #[cfg(test)]
    Probe,
}
fn production() {
    let _ = PgPool::connect(url);
}
";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

/// A `#[cfg(test)]` match arm drops only its own dial; the next item is scanned.
#[test]
fn cfg_test_match_arm_does_not_hide_the_next_item() {
    let fixture = r"
fn pick(x: u8) {
    match x {
        #[cfg(test)]
        0 => { let _ = PgPool::connect(test_only); },
        _ => {}
    }
}
fn production() {
    let _ = PgPool::connect(url);
}
";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

/// A `#[cfg(test)]` statement drops only itself; the next statement is scanned.
#[test]
fn cfg_test_statement_does_not_hide_the_next_statement() {
    let fixture = r"
fn production() {
    #[cfg(test)]
    let _ = PgPool::connect(test_only);
    let _ = PgPool::connect(url);
}
";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

#[test]
fn braces_in_char_literals_comments_and_strings_are_not_code() {
    let fixture = r##"
#[cfg(test)]
fn only_in_tests() {
    let a = '{';
    /* a comment with a brace { inside /* nested { */ it */
    let b = r#"a"{"#;
}

fn production() {
    let s = "before
#[cfg(test)]
after";
    PgPool::connect(url);
}
"##;
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production: raw dial `connect`",
    );
}

#[test]
fn cfg_all_test_is_dropped() {
    let fixture = r#"
#[cfg(all(test, feature = "x"))]
fn only_in_tests() { PgPool::connect(t); }

fn production() { PgPool::connect(url); }
"#;
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn production",
    );
}

/// `any(test, …)`, `not(test)`, and `feature = "test"` can each hold outside
/// a test build, so the item stays scanned.
#[test]
fn cfg_that_can_hold_outside_tests_is_scanned() {
    let fixture = r#"
#[cfg(any(test, feature = "x"))]
fn maybe_in_production() { PgPool::connect(a); }
#[cfg(not(test))]
fn production_only_outside_tests() { PgPool::connect(b); }
#[cfg(feature = "test")]
fn production_feature_test() { PgPool::connect(c); }
"#;
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        3,
        "raw dial `connect`",
    );
}

/// An unbalanced source does not parse, so it can never scan green.
#[test]
fn unbalanced_source_does_not_parse() {
    for fixture in [
        "#[cfg(test)]\nmod t {\n    fn helper() {\n",
        "fn production() {}\n#[cfg(test)]\nmod t {\n    fn helper() {\n    }\n",
    ] {
        assert!(syn::parse_file(fixture).is_err(), "{fixture}");
    }
}

// ---------------------------------------------------------------------------
// Refusal tests for the dial scans.
// ---------------------------------------------------------------------------

#[test]
fn raw_dial_scan_admits_only_vetted_pool_calls_and_definitions() {
    let fixture = "
use crate::db::VettedPool;
async fn open(url: &str) {
    let a = crate::db::VettedPool::<sqlx::Postgres>::connect(url, 4).await;
    let b = VettedPool::<sqlx::Sqlite>::
        connect(url, 4).await;
}
pub async fn connect(url: &str) {}
";
    assert_eq!(
        caller_url_violations("fixture.rs", fixture),
        Vec::<String>::new()
    );
}

/// A comment naming sqlite or a file never exempts a raw dial.
#[test]
fn raw_dial_scan_refuses_a_method_dial_a_comment_calls_local() {
    let fixture = "async fn open(url: &str) {
    // Local sqlite file at :memory:, no host to gate (SqlitePool).
    let _ = options.connect(url).await;
}
";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "fn open: raw dial `connect`",
    );
}

#[test]
fn raw_dial_scan_refuses_every_path_form() {
    let fixture = "async fn open(url: &str) {
    let _ = PgPool::connect(url).await;
    let _ = sqlx::postgres::PgPool::connect_lazy(url);
    let _ = sqlx::Pool::<Postgres>::connect_with(opts).await;
    let _ = ConnectOptions::connect(&opts).await;
    let _ = <PgConnection as Connection>::connect(url).await;
    let f = SqlitePool::connect;
    let _ = PgPoolOptions::new();
    let _ = r#connect(url);
    let _ = <VettedPool as Trait>::connect(url);
    let _ = crate::elsewhere::VettedPool::connect(url);
}
";
    let violations = caller_url_violations("fixture.rs", fixture);
    assert_violations(&violations, 10, "raw dial");
    assert!(
        violations.iter().any(|v| v.contains("`PgPoolOptions`")),
        "{violations:#?}"
    );
}

/// `VettedPool` spelled in a comment or a string does not own the call after it.
#[test]
fn raw_dial_scan_ignores_a_gate_named_in_a_comment_or_string() {
    let fixture = r#"async fn open(url: &str) {
    let _ = /* VettedPool:: */ PgPool::connect(url).await;
    let s = "VettedPool::"; connect(url);
}
"#;
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        2,
        "raw dial `connect`",
    );
}

/// A dial inside a macro body is still a dial, whether the body parses as
/// expressions or only as tokens.
#[test]
fn raw_dial_scan_reads_macro_bodies() {
    let fixture = "async fn open(url: &str) {
    let _ = vec![PgPool::connect(url)];
    tokio::select! {
        pool = PgPool::connect_with(opts) => { let _ = pool; }
    }
    macro_rules! dial { ($u:expr) => { SqlitePool::connect($u) }; }
}
";
    assert_violations(&caller_url_violations("fixture.rs", fixture), 3, "raw dial");
}

/// A raw pool renamed, aliased, or declared as `VettedPool` would otherwise
/// pass as the gate, and a renamed dial or opener would hide from the scan, so
/// every such definition is refused.
#[test]
fn raw_dial_scan_refuses_a_forged_gate_name() {
    for fixture in [
        "use sqlx::PgPool as VettedPool;\nfn f() { VettedPool::connect(url); }\n",
        "use crate::elsewhere::VettedPool;\nfn f() { VettedPool::connect(url); }\n",
        "type VettedPool = sqlx::PgPool;\nfn f() { VettedPool::connect(url); }\n",
        "mod VettedPool { pub fn connect() {} }\nfn f() { VettedPool::connect(url); }\n",
        "fn f<VettedPool: Pool>() { VettedPool::connect(url); }\n",
        "struct VettedPool;\nfn f() { VettedPool::connect(url); }\n",
        "use sqlx::PgPool::connect as open;\n",
        "use sqlx::postgres::PgPoolOptions as Opts;\n",
    ] {
        let violations = caller_url_violations("fixture.rs", fixture);
        assert_eq!(violations.len(), 1, "{fixture}\n{violations:#?}");
    }
}

/// The gate a fixture's `VettedPool::connect` must route through.
const GATED_POOL_FIXTURE: &str = r"
impl<DB> VettedPool<DB> {
    pub async fn connect(url: &str) -> Result<Self, E> {
        let options = DB::gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;
        Ok(Self(pool))
    }
}
";

/// A `VettedPool::connect` gate whose body before `Ok(Self(pool))` is `body`.
fn gate_with_body(body: &str) -> String {
    format!(
        "impl<DB> VettedPool<DB> {{
    pub async fn connect(url: &str) -> Result<Self, E> {{
{body}
        Ok(Self(pool))
    }}
}}
"
    )
}

#[test]
fn db_gate_scan_admits_the_gated_pool_fixture() {
    assert_eq!(
        db_dials_bypassing_the_gate("fixture.rs", GATED_POOL_FIXTURE),
        Vec::<String>::new()
    );
}

/// A comment naming sqlite or a file above a raw dial does not exempt it.
#[test]
fn db_gate_scan_refuses_a_dial_a_doc_comment_calls_local() {
    let fixture = format!(
        "{GATED_POOL_FIXTURE}
/// Opens the local sqlite file at :memory: (no host to gate).
async fn sneaky(url: &str) {{
    let _ = options.connect(url).await;
}}
"
    );
    assert_violations(
        &db_dials_bypassing_the_gate("fixture.rs", &fixture),
        1,
        "fn sneaky: raw dial `connect` outside",
    );
}

#[test]
fn db_gate_scan_refuses_a_path_form_dial_outside_the_gate() {
    let fixture = format!(
        "{GATED_POOL_FIXTURE}
async fn sneaky(url: &str) {{
    let _ = PgPool::connect(url).await;
    let _ = sqlx::Pool::<Sqlite>::connect_lazy(url);
}}
"
    );
    assert_violations(
        &db_dials_bypassing_the_gate("fixture.rs", &fixture),
        2,
        "outside VettedPool::connect",
    );
}

/// A string literal that spells a dial is not a dial, and a comment or string
/// inside the gate body that spells the gate call does not stand in for it.
#[test]
fn db_gate_scan_reads_code_not_comments_or_strings() {
    let fixture = r#"
impl<DB> VettedPool<DB> {
    pub async fn connect(url: &str) -> Result<Self, E> {
        // let options = DB::gated_connect_options(url).await?;
        let s = "DB::gated_connect_options(url)";
        let pool = PoolOptions::<DB>::new().connect(url).await?;
        Ok(Self(pool))
    }
}

fn label() -> &'static str {
    "PoolOptions::new().connect(url)"
}
"#;
    assert_violations(
        &db_dials_bypassing_the_gate("fixture.rs", fixture),
        1,
        "does not take its options",
    );
}

#[test]
fn db_gate_scan_refuses_a_second_dial_inside_the_gate() {
    let fixture = gate_with_body(
        "        let options = DB::gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;
        let raw = PgPool::connect(url).await?;",
    );
    assert_violations(
        &db_dials_bypassing_the_gate("fixture.rs", &fixture),
        1,
        "holds 2 raw dials",
    );
}

/// The gate's dial must take the gated binding itself: a different argument,
/// a shadowed or reassigned binding, or options from any other function is
/// refused.
#[test]
fn db_gate_scan_refuses_a_dial_whose_argument_is_not_the_gated_options() {
    for body in [
        // The gated options are computed but other options are dialled.
        "        let options = DB::gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(raw_options(url)).await?;",
        // The gated binding is shadowed before the dial.
        "        let options = DB::gated_connect_options(url).await?;
        let options = raw_options(url);
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;",
        // The gated binding is reassigned before the dial.
        "        let mut options = DB::gated_connect_options(url).await?;
        options = raw_options(url);
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;",
        // The options come from a same-named function that is not the driver's gate.
        "        let options = gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;",
        // The options come from a fixed driver's gate, not the pool's own.
        "        let options = sqlx::Postgres::gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;",
    ] {
        let fixture = gate_with_body(body);
        assert_violations(
            &db_dials_bypassing_the_gate("fixture.rs", &fixture),
            1,
            "does not take its options",
        );
    }
}

#[test]
fn db_gate_scan_refuses_a_missing_gate() {
    let fixture = "async fn open(url: &str) {\n    let _ = SqlitePool::connect(url).await;\n}\n";
    let violations = db_dials_bypassing_the_gate("fixture.rs", fixture);
    assert_eq!(violations.len(), 2, "{violations:#?}");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("0 VettedPool::connect bodies")),
        "{violations:#?}"
    );
}

/// A `VettedPool::connect` inside a trait impl is not the inherent gate.
#[test]
fn db_gate_scan_refuses_a_trait_impl_posing_as_the_gate() {
    let fixture = r"
impl<DB> Open for VettedPool<DB> {
    async fn connect(url: &str) -> Result<Self, E> {
        let options = DB::gated_connect_options(url).await?;
        let pool = PoolOptions::<DB>::new().connect_with(options).await?;
        Ok(Self(pool))
    }
}
";
    let violations = db_dials_bypassing_the_gate("fixture.rs", fixture);
    assert!(
        violations
            .iter()
            .any(|v| v.contains("0 VettedPool::connect bodies")),
        "{violations:#?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| v.contains("outside VettedPool::connect")),
        "{violations:#?}"
    );
}

#[test]
fn db_gate_scan_refuses_a_renamed_gate() {
    let fixture = format!("{GATED_POOL_FIXTURE}\nuse sqlx::PgPool as VettedPool;\n");
    assert_violations(
        &db_dials_bypassing_the_gate("fixture.rs", &fixture),
        1,
        "renames `PgPool` as `VettedPool`",
    );
}

#[test]
fn smtp_scan_admits_a_vetted_host() {
    let fixture = "async fn send() {
    let vetted = VettedDial::for_configured_host(&host, port).await?;
    let tb = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(
        vetted.dial_host(&cfg.host),
    );
}
";
    assert_eq!(
        ungated_smtp_transports("fixture.rs", fixture),
        Vec::<String>::new()
    );
}

/// A guard named only in a comment or a string never vouches for a transport,
/// nor does one inside a macro body that parses only as tokens.
#[test]
fn smtp_scan_refuses_a_guard_in_a_comment_or_string() {
    let fixture = r#"async fn send() {
    // let vetted = VettedDial::for_configured_host(&host, port); vetted.dial_host(h)
    let a = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host);
    let b = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("vetted.dial_host(h)");
    let c = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host);
    tokio::select! { t = relay(vetted.dial_host(h)) => {} }
}
"#;
    assert_violations(
        &ungated_smtp_transports("fixture.rs", fixture),
        4,
        "dials an unvetted host",
    );
}

// ---------------------------------------------------------------------------
// Refusal tests for gate paths, forged hosts, macro bodies, and verbatim syntax.
// ---------------------------------------------------------------------------

/// `VettedPool` is the gate only as itself or through `crate::db` or
/// `super::db`; any other module path, or a leading `::`, may name a forgery.
#[test]
fn raw_dial_scan_admits_vetted_pool_only_through_its_own_module() {
    let admitted = "use super::db::VettedPool;
use crate::{db::{DbUrl, VettedPool}};
fn open(url: &str) {
    super::db::VettedPool::connect(url);
    crate::db::VettedPool::<sqlx::Sqlite>::connect(url);
    VettedPool::connect(url);
}
";
    assert_eq!(
        caller_url_violations("fixture.rs", admitted),
        Vec::<String>::new()
    );
    for fixture in [
        "fn f() { evil::db::VettedPool::connect(url); }\n",
        "fn f() { self::db::VettedPool::connect(url); }\n",
        "fn f() { ::db::VettedPool::connect(url); }\n",
        "fn f() { crate::db::inner::VettedPool::connect(url); }\n",
        "fn f() { crate::evil::db::VettedPool::connect(url); }\n",
        "use evil::db::VettedPool;\n",
        "use self::db::VettedPool;\n",
        "use super::super::db::VettedPool;\n",
        "use ::db::VettedPool;\n",
        "use crate::evil::{db::VettedPool};\n",
        "use VettedPool;\n",
    ] {
        let violations = caller_url_violations("fixture.rs", fixture);
        assert_eq!(violations.len(), 1, "{fixture}\n{violations:#?}");
    }
}

/// `dial_host` defined anywhere but inherently on `VettedDial` in `ssrf.rs`
/// would let an unvetted host pass as a vetted one, so every such definition
/// is refused, and `ssrf.rs` defines exactly one.
#[test]
fn smtp_scan_refuses_a_forged_vetted_host() {
    let home = "impl VettedDial {
    pub(crate) fn dial_host(self, host: &str) -> String { host.to_owned() }
}
";
    assert_eq!(
        ungated_smtp_transports("ssrf.rs", home),
        Vec::<String>::new()
    );
    for (name, fixture) in [
        (
            "email.rs",
            "impl Forged { fn dial_host(&self, h: &str) -> String { h.to_owned() } }\n",
        ),
        (
            "email.rs",
            "impl VettedDial { fn dial_host(self, h: &str) -> String { h.to_owned() } }\n",
        ),
        (
            "email.rs",
            "fn dial_host(h: &str) -> String { h.to_owned() }\n",
        ),
        (
            "email.rs",
            "trait Host { fn dial_host(&self) -> String; }\n",
        ),
        ("email.rs", "extern \"C\" { fn dial_host(); }\n"),
        (
            "email.rs",
            "macro_rules! forge { () => { fn dial_host() {} }; }\n",
        ),
        (
            "email.rs",
            "fn send() { run! { fn dial_host() -> String { String::new() } } }\n",
        ),
        (
            "ssrf.rs",
            "impl VettedDial { fn dial_host(self) -> String { String::new() } }
impl Other { fn dial_host(self) -> String { String::new() } }
",
        ),
        (
            "ssrf.rs",
            "impl VettedDial { fn dial_host(self) -> String { String::new() } }
impl Host for VettedDial { fn dial_host(self) -> String { String::new() } }
",
        ),
    ] {
        assert_violations(
            &ungated_smtp_transports(name, fixture),
            1,
            "defines `dial_host`",
        );
    }
    for fixture in [
        "",
        "impl VettedDial { fn dial_host(self) -> String { String::new() } }
impl VettedDial { fn dial_host(self) -> String { String::new() } }
",
    ] {
        assert_violations(
            &ungated_smtp_transports("ssrf.rs", fixture),
            1,
            "exactly one is the gate",
        );
    }
}

/// A macro decides what the attributes in its body mean, so a
/// `#[cfg(test)]` there removes nothing from the scan.
#[test]
fn cfg_test_inside_a_macro_body_is_not_honoured() {
    for fixture in [
        "fn production() {
    run! {
        #[cfg(test)]
        let _ = PgPool::connect(url);
    }
}
",
        "fn production() {
    run! {
        #[cfg(test)]
        fn helper() { PgPool::connect(url); }
    }
}
",
        "fn production() {
    let _ = vec![#[cfg(test)] PgPool::connect(url)];
}
",
    ] {
        assert_violations(
            &caller_url_violations("fixture.rs", fixture),
            1,
            "raw dial `connect`",
        );
    }
}

/// Syntax `syn` keeps only as tokens is scanned token by token, so a dial
/// inside a verbatim item or expression is still a dial.
#[test]
fn raw_dial_scan_reads_verbatim_syntax() {
    for fixture in [
        "static OPEN = PgPool::connect(url);\n",
        "impl Pool { const OPEN<T>: u8 = PgPool::connect(url); }\n",
        "trait Open { const OPEN<T>: u8 = PgPool::connect(url); }\n",
        "extern \"C\" { fn open() { PgPool::connect(url); } }\n",
        "fn production() { become PgPool::connect(url) }\n",
        "fn production() { let _ = builtin # offset_of(PgPool::connect(url)); }\n",
    ] {
        assert_violations(
            &caller_url_violations("fixture.rs", fixture),
            1,
            "raw dial `connect`",
        );
    }
}

/// A macro body that defines `VettedPool` is a forgery, even as bare tokens.
#[test]
fn raw_dial_scan_refuses_a_gate_defined_in_a_macro_body() {
    let fixture = "macro_rules! forge { () => { struct VettedPool; }; }\n";
    assert_violations(
        &caller_url_violations("fixture.rs", fixture),
        1,
        "defines `struct VettedPool`",
    );
}

/// An allowed dial admits exactly its own path in its own function, once.
#[test]
fn allowed_dials_admit_only_their_own_dial_once() {
    let admitted = "async fn wait_ready(port: u16) {
    let _ = tokio::net::TcpStream::connect((\"127.0.0.1\", port)).await;
}
";
    assert_eq!(
        tree_violations("web/console_proxy.rs", admitted),
        Vec::<String>::new()
    );
    for (fixture, needle) in [
        (
            "async fn wait_ready(port: u16) {
    let _ = tokio::net::TcpStream::connect(a).await;
    let _ = tokio::net::TcpStream::connect(b).await;
}
",
            "matches 2 dials",
        ),
        (
            "async fn wait_ready(port: u16) {
    let _ = tokio::net::TcpStream::connect(a).await;
    let _ = PgPool::connect(url).await;
}
",
            "raw dial `connect`",
        ),
        (
            "async fn wait_ready(port: u16) {
    let _ = TcpStream::connect(a).await;
}
",
            "",
        ),
    ] {
        let violations = tree_violations("web/console_proxy.rs", fixture);
        assert!(!violations.is_empty(), "{fixture}");
        assert!(
            violations.iter().any(|v| v.contains(needle)),
            "{fixture}\n{violations:#?}"
        );
    }
    let elsewhere = "async fn elsewhere(port: u16) {
    let _ = tokio::net::TcpStream::connect(a).await;
}
";
    let violations = tree_violations("web/console_proxy.rs", elsewhere);
    assert_eq!(violations.len(), 2, "{violations:#?}");
    assert!(
        violations
            .iter()
            .any(|v| v.contains("fn elsewhere: raw dial `connect`")),
        "{violations:#?}"
    );
    assert!(
        violations.iter().any(|v| v.contains("matches 0 dials")),
        "{violations:#?}"
    );
    assert_violations(
        &tree_violations("other.rs", admitted),
        1,
        "fn wait_ready: raw dial `connect`",
    );
}

// ---------------------------------------------------------------------------
// The dial scans over the runtime's dial sites.
// ---------------------------------------------------------------------------

/// Whether `scan` walked a body of `func` whose enclosing `impl` type is `impl_of`.
fn has_fn(scan: &Scan, impl_of: Option<&str>, func: &str) -> bool {
    scan.fns
        .iter()
        .any(|f| f.impl_of.as_deref() == impl_of && f.func.as_deref() == Some(func))
}

/// The files that open a pool from a caller-supplied connection URL must do so
/// only through `VettedPool::connect`, never a raw sqlx opener, whose error may
/// echo the URL's credentials and which skips the SSRF gate.
#[test]
fn caller_url_pools_open_only_through_vetted_pool() {
    let sources = [
        ("web/store.rs", include_str!("../src/web/store.rs"), None),
        (
            "external_conn.rs",
            include_str!("../src/external_conn.rs"),
            Some("open_external"),
        ),
    ];
    for (name, src, anchor_fn) in sources {
        let walked = scan(name, src);
        let gated_calls = walked.dials.iter().filter(|d| d.gated).count();
        assert!(
            gated_calls >= 2,
            "{name}: expected its VettedPool::connect calls to be walked, found {gated_calls}"
        );
        if let Some(func) = anchor_fn {
            assert!(has_fn(&walked, None, func), "{name}: fn {func} not walked");
        }
        assert_eq!(
            caller_url_violations(name, src),
            Vec::<String>::new(),
            "raw sqlx dial in {name}: open through VettedPool::connect"
        );
    }
}

#[test]
fn db_pool_connect_is_guarded() {
    let src = include_str!("../src/db.rs");
    let walked = scan("db.rs", src);
    for (impl_of, func) in [
        (None, "build_pool"),
        (None, "vet_dial_target"),
        (Some(GATED_OWNER), "connect"),
        (Some("Postgres"), GATE_OPTIONS_FN),
        (Some("Sqlite"), GATE_OPTIONS_FN),
    ] {
        assert!(
            has_fn(&walked, impl_of, func),
            "db.rs: {impl_of:?} fn {func} not walked"
        );
    }
    assert_eq!(
        walked.gate_structs, 1,
        "db.rs defines `struct VettedPool` once"
    );
    assert!(
        walked
            .dials
            .iter()
            .any(|d| d.gated && d.within.func.as_deref() == Some("build_pool")),
        "db.rs: build_pool opens through VettedPool::connect"
    );
    assert_eq!(
        db_dials_bypassing_the_gate("db.rs", src),
        Vec::<String>::new()
    );
}

#[test]
fn email_smtp_transport_is_guarded() {
    let src = include_str!("../src/email.rs");
    let walked = scan("email.rs", src);
    assert!(
        has_fn(&walked, None, "send_smtp"),
        "email.rs: fn send_smtp not walked"
    );
    assert!(
        walked
            .transports
            .iter()
            .any(|t| t.name == "builder_dangerous" && t.within.func.as_deref() == Some("send_smtp")),
        "email.rs: send_smtp's transport not walked"
    );
    assert_eq!(
        ungated_smtp_transports("email.rs", src),
        Vec::<String>::new(),
        "SMTP transport in email.rs built from an unvetted host: pass VettedDial::dial_host"
    );
}

// ---------------------------------------------------------------------------
// The dial scans over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// The most directory entries the source walk reads before it fails.
const MAX_SOURCE_ENTRIES: usize = 8192;

/// Every `.rs` file under `root`, as its `/`-separated path relative to `root`
/// and its contents, sorted by path.
///
/// A symbolic link is refused rather than followed or skipped, so every file
/// the build can read is one the walk read.
#[allow(clippy::expect_used)] // an unreadable source must fail the scan, never be skipped
fn rust_sources(root: &Path) -> Vec<(String, String)> {
    let mut dirs: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut files: Vec<PathBuf> = Vec::new();
    let mut entries = 0usize;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read a source directory") {
            let entry = entry.expect("read a source directory entry");
            entries = entries.saturating_add(1);
            assert!(
                entries <= MAX_SOURCE_ENTRIES,
                "more than {MAX_SOURCE_ENTRIES} entries under {}",
                root.display()
            );
            let kind = entry.file_type().expect("read a source entry's type");
            let path = entry.path();
            assert!(
                !kind.is_symlink(),
                "{}: a symbolic link in the source tree is not scanned",
                path.display()
            );
            if kind.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    let mut sources: Vec<(String, String)> = files
        .iter()
        .map(|path| {
            let name = path
                .strip_prefix(root)
                .expect("a walked file lies under the root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            (
                name,
                std::fs::read_to_string(path).expect("read a source file"),
            )
        })
        .collect();
    sources.sort();
    sources
}

/// Every source file under `src/` passes every dial rule, and every allowed
/// dial names a file the walk read.
#[test]
fn every_runtime_source_passes_every_dial_rule() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = rust_sources(&root);
    let read = |file: &str| sources.iter().any(|(name, _)| name == file);
    for required in [
        GATED_OWNER_FILE,
        VETTED_HOST_FILE,
        "email.rs",
        "external_conn.rs",
        "web/store.rs",
    ] {
        assert!(read(required), "the source walk did not read {required}");
    }
    for entry in &ALLOWED_DIALS {
        assert!(
            read(entry.file),
            "an allowed dial names {}, which the source walk did not read",
            entry.file
        );
    }
    let violations: Vec<String> = sources
        .iter()
        .flat_map(|(name, src)| tree_violations(name, src))
        .collect();
    assert_eq!(violations, Vec::<String>::new());
}

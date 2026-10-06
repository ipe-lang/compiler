#![forbid(unsafe_code)]
//! Proves every child process the `ipe` crate starts reaches one bounded runner.
//!
//! A child started outside a runner has no output ceiling, no wall and no
//! descriptor floor. The runners are a closed set: `run_local` and
//! `run_local_fed` under a named `LocalCeiling`, the `Git`/`Curl` transfers,
//! the cargo owner, `run_inherited` under a named `InheritedRole`,
//! `exec_naming`, the browser opener and `run_probe`.
//!
//! The scan walks the crate's module tree from each crate root, parsing every
//! reached file with `syn`. An item, impl item, trait item or `mod` whose `cfg`
//! is `test`, an `all(..)` holding `test`, or an `any(..)` of test-only
//! predicates is test code; every other `cfg` is production, so an unrecognised
//! shape can only turn the scan red. A source file the walk never reaches, a
//! `#[path]` module and an `include!` are refused, since each would hide source.
//!
//! In production code it collects:
//!
//! - every `Command::new` (a site), keyed by file, enclosing fn and the rendered
//!   program expression, held to [`SITES`]; each row names the runner the site
//!   reaches and is proved from the syntax tree, not trusted;
//! - every direct child start (a call whose path ends in a [`SINK_FNS`] name, or
//!   a [`SINK_METHODS`] name qualified by `Command`, `CommandExt` or `Child`),
//!   held to [`RUNNER_BODIES`];
//! - every zero-argument call of a [`SINK_METHODS`] name, whatever its
//!   receiver, held to [`METHODS`], so a raw `.output()` is red and a non-child
//!   `.status()` is admitted only by its own row.
//!
//! Names are compared with any `r#` prefix removed, and a qualified path
//! `<T>::f` or `<T as Tr>::f` is read with `T` before `f`; a qualified path
//! whose self type has no name is refused. Macro bodies are parsed as
//! comma-separated expressions, or else matched token by token; there a
//! method name or a child-type path segment a macro metavariable supplies is
//! refused, and every identifier counts as a use and a binding of its name.
//! A renaming `use` of `Command`, `CommandExt`, `Child`, `LocalCeiling`,
//! `InheritedRole` or a runner fn, a type alias naming `Command`, `CommandExt`
//! or `Child`, and a `Command::new` not called in place are refused.
//!
//! A ceiling is named only by the top-level `LocalCeiling` consts of
//! `remote_ingest.rs`: a `LocalCeiling` const elsewhere, any const, static,
//! binding or renaming `use` sharing a ceiling's name, and a fn outside
//! `remote_ingest.rs` named as a runner or a sink fn are refused, so a name the
//! proof matches cannot stand for another value. A ceiling parameter or a
//! helper's ceiling parameter must be bound once in its fn, and a fn key two
//! items share proves nothing. A `ureq` body read is held to
//! `remote_ingest::read_capped` by a whitespace-free text match.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Ident, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprMethodCall, ExprPath, FnArg, ImplItem, ImplItemType, Item, ItemImpl,
    ItemMod, ItemType, Lit, Macro, Member, Meta, Pat, PatIdent, ReturnType, Signature, Token,
    TraitItem, TraitItemType, Type, UseTree,
};

/// The runner a child site reaches, as its [`SITES`] row names it.
#[derive(Clone, Copy, Debug)]
enum Runner {
    /// `run_local(cmd, CEILING, source)`, with the named `LocalCeiling`.
    Local(&'static str),
    /// `run_local_fed(cmd, stdin, CEILING, source)`, with the named `LocalCeiling`.
    LocalFed(&'static str),
    /// A `Git` or `Curl` constructor in `remote_ingest.rs`.
    Transfer,
    /// The cargo owner, `cargo_step.rs`.
    Cargo,
    /// `run_inherited(cmd, InheritedRole::ROLE, input)`, with the named role.
    Inherited(&'static str),
    /// `exec_naming`, which replaces the process.
    Replace,
    /// The browser opener, `browser.rs::open_url`.
    Opener,
    /// `remote_ingest::run_probe`, the attached signal-mask probe.
    Probe,
    /// The named fn, itself a [`RUNNER_BODIES`] row of the same file.
    Body(&'static str),
}

/// One child site row: file relative to `src/`, enclosing fn, rendered program
/// expression, runner, count.
type SiteRow = (&'static str, &'static str, &'static str, Runner, usize);

/// One name row: file relative to `src/`, enclosing fn, called name, count.
type NameRow = (&'static str, &'static str, &'static str, usize);

/// Every production `Command::new`, with the runner it reaches.
///
/// Several rows on one (file, fn, program) key share its count, each proving
/// its own runner in that fn (a `cfg(unix)` and a `cfg(not(unix))` block).
const SITES: &[SiteRow] = &[
    (
        "audit.rs",
        "detect_cargo_deny_minor",
        "cargo_deny",
        Runner::Local("TOOL_QUERY_LIMITS"),
        1,
    ),
    (
        "audit.rs",
        "run_cargo_deny",
        "cargo_deny",
        Runner::Local("SUPPLY_CHAIN_SCAN_LIMITS"),
        1,
    ),
    ("browser.rs", "open_url", "program", Runner::Opener, 1),
    (
        "build_plan.rs",
        "installed_targets_of",
        "rustup",
        Runner::Local("TOOL_QUERY_LIMITS"),
        1,
    ),
    ("cargo_step.rs", "build_command", "cargo", Runner::Cargo, 1),
    (
        "cargo_step.rs",
        "lock_dependencies_within",
        "build.get_program()",
        Runner::Local("LOCK_FETCH_LIMITS"),
        1,
    ),
    (
        "cargo_step.rs",
        "lock_offline_within",
        "cargo",
        Runner::Local("LOCK_RESOLVE_LIMITS"),
        1,
    ),
    (
        "cargo_step.rs",
        "target_directory_within",
        "cargo.path()",
        Runner::Local("METADATA_LIMITS"),
        1,
    ),
    (
        "coverage/probe.rs",
        "build_and_run",
        "&ipe_bin",
        Runner::Local("SELF_RUN_LIMITS"),
        1,
    ),
    (
        "doc.rs",
        "run_example_and_check",
        "&ipe_bin",
        Runner::Local("SELF_RUN_LIMITS"),
        1,
    ),
    (
        "driver/commands.rs",
        "bundle_wasm_pkg",
        "tools.bindgen",
        Runner::Local("WASM_TOOL_LIMITS"),
        1,
    ),
    (
        "driver/commands.rs",
        "bundle_wasm_pkg",
        "tools.opt",
        Runner::Local("WASM_TOOL_LIMITS"),
        1,
    ),
    (
        "driver/commands.rs",
        "exec_program",
        "program",
        Runner::Replace,
        1,
    ),
    (
        "driver/commands.rs",
        "exec_program",
        "program",
        Runner::Inherited("UserProgram"),
        1,
    ),
    (
        "driver/commands.rs",
        "run_run_with_args",
        "&bin",
        Runner::Replace,
        1,
    ),
    (
        "driver/commands.rs",
        "run_run_with_args",
        "&bin",
        Runner::Inherited("UserProgram"),
        1,
    ),
    (
        "driver/commands_pkg.rs",
        "build_wasm_for_mobile",
        "&exe",
        Runner::Inherited("SelfBuild"),
        1,
    ),
    (
        "driver/commands_pkg.rs",
        "run_installer",
        "\"sh\"",
        Runner::Inherited("InteractiveInstall"),
        1,
    ),
    (
        "driver/commands_pkg.rs",
        "run_test_binary",
        "&bin",
        Runner::Inherited("UserProgram"),
        2,
    ),
    (
        "ffi.rs",
        "inspect_unsandboxed",
        "program",
        Runner::Local("FFI_INSPECT_LIMITS"),
        1,
    ),
    (
        "health.rs",
        "run_install",
        "program",
        Runner::Inherited("InteractiveInstall"),
        1,
    ),
    (
        "health.rs",
        "run_link_probe",
        "\"rustc\"",
        Runner::LocalFed("LINK_PROBE_LIMITS"),
        1,
    ),
    (
        "remote_ingest.rs",
        "Curl::https",
        "\"curl\"",
        Runner::Transfer,
        1,
    ),
    (
        "remote_ingest.rs",
        "Git::base",
        "\"git\"",
        Runner::Transfer,
        1,
    ),
    ("terminate.rs", "ps_masks", "\"/bin/ps\"", Runner::Probe, 1),
    (
        "toolchain.rs",
        "RustcVersion::active",
        "\"rustc\"",
        Runner::Local("RUSTC_QUERY_LIMITS"),
        1,
    ),
    (
        "watch.rs",
        "child_command",
        "exe_path",
        Runner::Body("spawn_command"),
        1,
    ),
];

/// Every runner body: the fns that start a child directly, by the sink they call.
const RUNNER_BODIES: &[NameRow] = &[
    ("browser.rs", "run_opener", "spawn_hardened", 1),
    ("cargo_step.rs", "spawn_cargo", "spawn_hardened", 1),
    ("driver/commands.rs", "exec_program", "exec_naming", 1),
    ("driver/commands.rs", "run_run_with_args", "exec_naming", 1),
    ("remote_ingest.rs", "Running::spawn", "spawn_attached", 1),
    ("remote_ingest.rs", "Running::spawn", "spawn_detached", 1),
    ("remote_ingest.rs", "Running::spawn", "spawn_hardened", 1),
    (
        "remote_ingest.rs",
        "group::spawn_attached",
        "spawn_hardened",
        2,
    ),
    (
        "remote_ingest.rs",
        "group::spawn_detached",
        "spawn_hardened",
        2,
    ),
    ("remote_ingest.rs", "run_inherited", "spawn_hardened", 1),
    ("watch.rs", "spawn_command", "spawn_hardened", 1),
];

/// Every admitted zero-argument call of a child-start method name, keyed by
/// its rendered receiver and name: a non-child receiver (an HTTP response's
/// `status()`) or a runner's own method.
const METHODS: &[NameRow] = &[
    (
        "ssh_signing_key.rs",
        "post_signing_key",
        "response.status",
        2,
    ),
    ("watch.rs", "spawn_cargo_build", "build.spawn", 1),
];

/// The rows a judgement holds the scanned sources to.
struct Inventory<'a> {
    sites: &'a [SiteRow],
    bodies: &'a [NameRow],
    methods: &'a [NameRow],
}

/// The crate's own rows.
const INVENTORY: Inventory<'static> = Inventory {
    sites: SITES,
    bodies: RUNNER_BODIES,
    methods: METHODS,
};

/// Fns that start a child directly: a call of one is a runner-body sink.
const SINK_FNS: &[&str] = &[
    "spawn_hardened",
    "spawn_hardened_naming",
    "spawn_hardened_tokio",
    "spawn_detached",
    "spawn_attached",
    "exec_naming",
];

/// Method names that start a child or wait on one.
const SINK_METHODS: &[&str] = &["spawn", "output", "status", "exec", "wait_with_output"];

/// The types a qualified [`SINK_METHODS`] path call starts a child through.
const CHILD_TYPES: &[&str] = &["Command", "CommandExt", "Child"];

/// The runner fns a renaming `use` may not rebind, beside [`CHILD_TYPES`] and [`SINK_FNS`].
const RUNNER_FNS: &[&str] = &["run_local", "run_local_fed", "run_inherited", "run_probe"];

/// The two path segments every child site calls.
const COMMAND_NEW: &[&str] = &["Command", "new"];

/// The file whose `LocalCeiling` consts are the only admitted ceilings.
const CEILING_OWNER: &str = "remote_ingest.rs";

/// The type of a named ceiling.
const CEILING_TYPE: &str = "LocalCeiling";

/// The type whose variants name an inherited run's role.
const ROLE_TYPE: &str = "InheritedRole";

/// The type a builder fn returns.
const COMMAND_TYPE: &str = "Command";

/// The runner fns a site proof looks for, with their ceiling argument position.
const RUN_LOCAL: (&str, usize) = ("run_local", 1);
const RUN_LOCAL_FED: (&str, usize) = ("run_local_fed", 2);
const RUN_INHERITED: &str = "run_inherited";
const RUN_PROBE: &str = "run_probe";
const EXEC_NAMING: &str = "exec_naming";

/// The qualifier a token-matched path takes when its self type has no name.
const UNNAMED_QUALIFIER: &str = "<unnamed>";

/// The qualifier a token-matched path takes when a macro metavariable supplies it.
const METAVAR_QUALIFIER: &str = "<metavariable>";

/// The receiver a token-matched method call renders with.
const MACRO_RECEIVER: &str = "<macro>";

/// The binding a glob `use` inside a fn stands for: any name.
const GLOB_BINDING: &str = "*";

/// The macro that splices a file the walk does not reach.
const INCLUDE_MACRO: &str = "include";

/// Module nesting the walk descends before refusing to go deeper.
const MAX_DEPTH: usize = 32;

/// Directory nesting the source-file listing descends before refusing.
const MAX_DIR_DEPTH: usize = 16;

/// One `fn` parameter: its binding name, when a plain identifier, and whether
/// its type is a `LocalCeiling`.
struct Param {
    name: Option<String>,
    ceiling: bool,
}

/// What a production fn's signature says.
struct FnSig {
    receiver: bool,
    params: Vec<Param>,
    returns_command: bool,
}

/// One production path call: the enclosing fn, the callee path, and each
/// argument's path segments when the argument is a path.
struct Call {
    within: String,
    callee: Vec<String>,
    args: Vec<Option<Vec<String>>>,
}

/// One (enclosing fn, name) fact.
type Named = (String, String);

/// What one parsed file contributes, production facts only, plus the module
/// files it declares, each with the directory its own children resolve in and
/// whether it is reached as production.
///
/// A fn key two production fns share maps to `None`, so no proof reads either.
#[derive(Default)]
struct FileScan {
    fns: BTreeMap<String, Option<FnSig>>,
    calls: Vec<Call>,
    methods: Vec<Named>,
    values: Vec<String>,
    sites: Vec<Named>,
    path_sinks: Vec<Named>,
    method_sinks: Vec<Named>,
    ceilings: Vec<String>,
    /// Every pattern binding, by enclosing fn.
    bindings: Vec<Named>,
    /// Every name a `use` brings into scope, by enclosing item.
    imports: Vec<Named>,
    /// Every identifier of a token-matched macro body, by enclosing item.
    macro_idents: Vec<Named>,
    /// Every const and static, by enclosing item.
    consts: Vec<Named>,
    /// Every renaming `use`, as (imported name, new name).
    renames: Vec<(String, String)>,
    refusals: Vec<String>,
    children: Vec<(PathBuf, PathBuf, bool)>,
}

/// Every scanned file, keyed relative to `src/`.
type Scans = BTreeMap<String, FileScan>;

/// Whether `name` is one of `names`.
fn listed(names: &[&str], name: &str) -> bool {
    names.contains(&name)
}

/// Whether `path` ends with the segments `tail`.
fn ends_with(path: &[String], tail: &[&str]) -> bool {
    path.len() >= tail.len()
        && path
            .iter()
            .rev()
            .zip(tail.iter().rev())
            .all(|(segment, want)| segment == want)
}

/// The last `::` component of a fn key.
fn last_component(key: &str) -> &str {
    key.rsplit("::").next().unwrap_or(key)
}

/// An identifier's name, any `r#` prefix removed.
fn name_of(ident: &Ident) -> String {
    ident.unraw().to_string()
}

/// Whether `qualifier` may name a type a child starts through: a child type,
/// or a qualifier the token matcher cannot name.
fn child_qualifier(qualifier: &str) -> bool {
    listed(CHILD_TYPES, qualifier)
        || qualifier == UNNAMED_QUALIFIER
        || qualifier == METAVAR_QUALIFIER
}

/// Whether the call path `path` starts a child directly.
fn is_path_sink(path: &[String]) -> bool {
    let Some((last, before)) = path.split_last() else {
        return false;
    };
    listed(SINK_FNS, last)
        || (listed(SINK_METHODS, last) && before.iter().any(|q| child_qualifier(q)))
}

/// Whether a renaming `use` of `name` is refused.
fn rename_refused(name: &str) -> bool {
    listed(CHILD_TYPES, name)
        || listed(RUNNER_FNS, name)
        || listed(SINK_FNS, name)
        || name == CEILING_TYPE
        || name == ROLE_TYPE
}

/// Whether the `cfg` predicate `meta` holds only under `cfg(test)`.
fn test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) => {
            let Ok(nested) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            if list.path.is_ident("all") {
                nested.iter().any(test_only)
            } else if list.path.is_ident("any") {
                !nested.is_empty() && nested.iter().all(test_only)
            } else {
                false
            }
        }
        Meta::NameValue(_) => false,
    }
}

/// Whether `attrs` hold a `cfg` that compiles the item only under `cfg(test)`.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .meta
                .require_list()
                .ok()
                .and_then(|list| syn::parse2::<Meta>(list.tokens.clone()).ok())
                .is_some_and(|meta| test_only(&meta))
    })
}

/// Whether `attr` is a `#[path]`, or a `#[cfg_attr]` that may expand to one.
fn names_a_path(attr: &Attribute) -> bool {
    attr.path().is_ident("path")
        || (attr.path().is_ident("cfg_attr")
            && attr.meta.require_list().is_ok_and(|list| {
                list.tokens
                    .clone()
                    .into_iter()
                    .any(|tree| matches!(tree, TokenTree::Ident(ident) if ident == "path"))
            }))
}

/// The last identifier of `ty`'s path, if it is a path type, parentheses and
/// invisible groups looked through.
fn type_last(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|seg| name_of(&seg.ident)),
        Type::Paren(inner) => type_last(&inner.elem),
        Type::Group(inner) => type_last(&inner.elem),
        _ => None,
    }
}

/// The name of a qualified path's self type, references and pointers looked
/// through; `None` when it has no path name (`<[T]>`, `<_>`, `<dyn Tr>`).
fn qself_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Reference(inner) => qself_name(&inner.elem),
        Type::Ptr(inner) => qself_name(&inner.elem),
        Type::Paren(inner) => qself_name(&inner.elem),
        Type::Group(inner) => qself_name(&inner.elem),
        _ => type_last(ty),
    }
}

/// The segments of an expression path, a qualified self type `<T>::f` or
/// `<T as Tr>::f` inserted before the last segment; `None` when the self type
/// has no name.
fn expr_path(path: &ExprPath) -> Option<Vec<String>> {
    let mut found = segments(&path.path);
    if let Some(qself) = &path.qself {
        let at = found.len().saturating_sub(1);
        found.insert(at, qself_name(&qself.ty)?);
    }
    Some(found)
}

/// The impl name an `impl` block's fns are keyed under.
fn impl_name(item: &ItemImpl) -> String {
    let self_name = type_last(&item.self_ty).unwrap_or_else(|| "<type>".to_owned());
    let Some((path, _)) = &item.trait_ else {
        return self_name;
    };
    let trait_name = path
        .segments
        .last()
        .map_or_else(String::new, |seg| name_of(&seg.ident));
    format!("<{self_name} as {trait_name}>")
}

/// The segments of `path`.
fn segments(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|seg| name_of(&seg.ident))
        .collect()
}

/// The binding name of a plain identifier pattern.
fn pat_ident(pat: &Pat) -> Option<String> {
    match pat {
        Pat::Ident(binding) => Some(name_of(&binding.ident)),
        _ => None,
    }
}

/// What `sig` says about receiver, parameters and return type.
fn fn_sig(sig: &Signature) -> FnSig {
    let mut receiver = false;
    let mut params = Vec::new();
    for input in &sig.inputs {
        match input {
            FnArg::Receiver(_) => receiver = true,
            FnArg::Typed(typed) => params.push(Param {
                name: pat_ident(&typed.pat),
                ceiling: type_last(&typed.ty).is_some_and(|name| name == CEILING_TYPE),
            }),
        }
    }
    let returns_command = match &sig.output {
        ReturnType::Type(_, ty) => type_last(ty).is_some_and(|name| name == COMMAND_TYPE),
        ReturnType::Default => false,
    };
    FnSig {
        receiver,
        params,
        returns_command,
    }
}

/// A struct field name or tuple index.
fn member(member: &Member) -> String {
    match member {
        Member::Named(ident) => name_of(ident),
        Member::Unnamed(index) => index.index.to_string(),
    }
}

/// The marker a call renders with: empty for no argument, `..` for any.
fn arguments_marker(args: &Punctuated<Expr, Token![,]>) -> &'static str {
    if args.is_empty() { "" } else { ".." }
}

/// The program expression of a site, rendered for its [`SITES`] key.
fn render(expr: &Expr) -> String {
    match expr {
        Expr::Lit(syn::ExprLit {
            lit: Lit::Str(text),
            ..
        }) => format!("\"{}\"", text.value()),
        Expr::Path(path) => expr_path(path).map_or_else(|| "<expr>".to_owned(), |p| p.join("::")),
        Expr::Reference(reference) => {
            let mutability = if reference.mutability.is_some() {
                "mut "
            } else {
                ""
            };
            format!("&{mutability}{}", render(&reference.expr))
        }
        Expr::Field(field) => format!("{}.{}", render(&field.base), member(&field.member)),
        Expr::MethodCall(call) => format!(
            "{}.{}({})",
            render(&call.receiver),
            name_of(&call.method),
            arguments_marker(&call.args)
        ),
        Expr::Call(call) => format!("{}({})", render(&call.func), arguments_marker(&call.args)),
        Expr::Paren(paren) => format!("({})", render(&paren.expr)),
        _ => "<expr>".to_owned(),
    }
}

/// The path segments of an argument, when it is a path.
fn arg_path(arg: &Expr) -> Option<Vec<String>> {
    match arg {
        Expr::Path(path) => expr_path(path),
        _ => None,
    }
}

/// The attributes of an item this scan knows the shape of.
fn item_attrs(item: &Item) -> Option<&[Attribute]> {
    let attrs: &[Attribute] = match item {
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
        _ => return None,
    };
    Some(attrs)
}

/// Whether `tree` is the punctuation `ch`.
fn is_punct(tree: &TokenTree, ch: char) -> bool {
    matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ch)
}

/// The qualifier before a `::` that ends `before`, if any: the identifier
/// before it, the [`angle_qualifier`] of a `<..>` before it, or
/// [`METAVAR_QUALIFIER`] for a `$name`.
fn qualifier_of(before: &[TokenTree]) -> Option<String> {
    let [rest @ .., first, second] = before else {
        return None;
    };
    if !is_punct(first, ':') || !is_punct(second, ':') {
        return None;
    }
    match rest {
        [.., dollar, TokenTree::Ident(_)] if is_punct(dollar, '$') => {
            Some(METAVAR_QUALIFIER.to_owned())
        }
        [.., TokenTree::Ident(qualifier)] => Some(name_of(qualifier)),
        [.., close] if is_punct(close, '>') => Some(angle_qualifier(rest)),
        _ => None,
    }
}

/// The qualifier the `<..>` ending `rest` names: a [`CHILD_TYPES`] name
/// anywhere inside it, else its first identifier, else [`UNNAMED_QUALIFIER`].
fn angle_qualifier(rest: &[TokenTree]) -> String {
    let mut depth = 0_usize;
    let mut inside = Vec::new();
    for tree in rest.iter().rev() {
        if is_punct(tree, '>') {
            depth = depth.saturating_add(1);
        } else if is_punct(tree, '<') {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                break;
            }
        } else if let TokenTree::Ident(ident) = tree {
            inside.push(name_of(ident));
        }
    }
    inside
        .iter()
        .find(|name| listed(CHILD_TYPES, name.as_str()))
        .or_else(|| inside.last())
        .cloned()
        .unwrap_or_else(|| UNNAMED_QUALIFIER.to_owned())
}

/// Whether `before` ends in a `.`.
fn follows_dot(before: &[TokenTree]) -> bool {
    before.last().is_some_and(|dot| is_punct(dot, '.'))
}

/// Whether `next` opens a turbofish `::<..>`.
fn opens_turbofish(next: Option<&TokenTree>) -> bool {
    next.is_some_and(|colon| is_punct(colon, ':'))
}

/// Whether `next` is an empty `( )` group.
fn empty_parens(next: Option<&TokenTree>) -> bool {
    matches!(next, Some(TokenTree::Group(group))
        if group.delimiter() == Delimiter::Parenthesis && group.stream().is_empty())
}

/// The syntax visitor for one file.
struct Scanner<'a> {
    /// The directory `mod x;` declarations at the current nesting resolve in.
    dir: PathBuf,
    /// The enclosing item path.
    context: Vec<String>,
    /// How many type aliases enclose the current node.
    in_alias: usize,
    /// Whether the current node is production code.
    production: bool,
    /// The file's display name, for refusals.
    file: &'a str,
    out: FileScan,
}

impl Scanner<'_> {
    fn key(&self) -> String {
        self.context.join("::")
    }

    fn refuse(&mut self, what: &str) {
        let key = self.key();
        self.out
            .refusals
            .push(format!("{}: {what} in `{key}`", self.file));
    }

    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.context.push(name);
        walk(self);
        self.context.pop();
    }

    fn gated(&mut self, test_code: bool, walk: impl FnOnce(&mut Self)) {
        let outer = self.production;
        self.production = outer && !test_code;
        walk(self);
        self.production = outer;
    }

    fn aliasing(&mut self, walk: impl FnOnce(&mut Self)) {
        self.in_alias = self.in_alias.saturating_add(1);
        walk(self);
        self.in_alias = self.in_alias.saturating_sub(1);
    }

    fn function(&mut self, sig: &Signature, walk: impl FnOnce(&mut Self)) {
        let name = name_of(&sig.ident);
        let impersonates = listed(RUNNER_FNS, &name) || listed(SINK_FNS, &name);
        self.within(name, |s| {
            if s.production {
                if impersonates && s.file != CEILING_OWNER {
                    s.refuse(&format!(
                        "a fn named as a runner or sink fn outside `{CEILING_OWNER}`"
                    ));
                }
                match s.out.fns.entry(s.key()) {
                    Entry::Vacant(slot) => {
                        slot.insert(Some(fn_sig(sig)));
                    }
                    Entry::Occupied(mut slot) => {
                        slot.insert(None);
                    }
                }
            }
            walk(s);
        });
    }

    /// Record one const or static named `ident` of type `ty`.
    fn constant(&mut self, ident: &Ident, ty: &Type) {
        if !self.production {
            return;
        }
        let name = name_of(ident);
        if type_last(ty).is_some_and(|last| last == CEILING_TYPE) {
            if self.file == CEILING_OWNER && self.context.is_empty() {
                self.out.ceilings.push(name.clone());
            } else {
                self.refuse(&format!(
                    "a `{CEILING_TYPE}` `{name}` outside the top level of `{CEILING_OWNER}`"
                ));
            }
        }
        let key = self.key();
        self.out.consts.push((key, name));
    }

    /// Record one name a `use` brings into scope.
    fn import(&mut self, name: String) {
        if self.production {
            let key = self.key();
            self.out.imports.push((key, name));
        }
    }

    fn path_sink(&mut self, name: String) {
        let key = self.key();
        self.out.path_sinks.push((key, name));
    }

    fn method_sink(&mut self, name: String) {
        let key = self.key();
        self.out.method_sinks.push((key, name));
    }

    fn site(&mut self, program: String) {
        let key = self.key();
        self.out.sites.push((key, program));
    }

    /// The segments of `path`, refusing a qualified path whose self type has no name.
    fn path_of(&mut self, path: &ExprPath) -> Option<Vec<String>> {
        let found = expr_path(path);
        if found.is_none() && self.production {
            self.refuse("a qualified path whose self type this scan cannot name");
        }
        found
    }

    fn path_call(&mut self, callee: Vec<String>, args: &Punctuated<Expr, Token![,]>) {
        if !self.production {
            return;
        }
        if ends_with(&callee, COMMAND_NEW) {
            let program = args.first().map_or_else(|| "<none>".to_owned(), render);
            self.site(program);
        }
        if is_path_sink(&callee)
            && let Some(last) = callee.last()
        {
            self.path_sink(last.clone());
        }
        let call = Call {
            within: self.key(),
            callee,
            args: args.iter().map(arg_path).collect(),
        };
        self.out.calls.push(call);
    }

    fn value_path(&mut self, path: &[String]) {
        if !self.production {
            return;
        }
        if ends_with(path, COMMAND_NEW) {
            self.refuse("a `Command::new` not called in place");
        }
        let Some(last) = path.last() else {
            return;
        };
        if is_path_sink(path) {
            self.path_sink(last.clone());
        }
        self.out.values.push(last.clone());
    }

    fn method_call(&mut self, call: &ExprMethodCall) {
        if !self.production {
            return;
        }
        let name = name_of(&call.method);
        let key = self.key();
        self.out.methods.push((key, name.clone()));
        if call.args.is_empty() && listed(SINK_METHODS, &name) {
            self.method_sink(format!("{}.{name}", render(&call.receiver)));
        }
    }

    /// Match the child-start shapes in a token stream no expression parse reads.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        if !self.production {
            return;
        }
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.scan_tokens(group.stream()),
                TokenTree::Ident(ident) => {
                    let before = trees.get(..at).unwrap_or_default();
                    let next = trees.get(at.saturating_add(1));
                    self.scan_token(ident, before, next);
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    fn scan_token(&mut self, ident: &Ident, before: &[TokenTree], next: Option<&TokenTree>) {
        let name = name_of(ident);
        let key = self.key();
        self.out.macro_idents.push((key, name.clone()));
        self.out.values.push(name.clone());
        if let [rest @ .., dollar] = before
            && is_punct(dollar, '$')
        {
            let child_path = qualifier_of(rest).is_some_and(|q| child_qualifier(&q));
            if follows_dot(rest) || child_path {
                self.refuse("a method or child-type path segment a macro metavariable supplies");
            }
            return;
        }
        let qualifier = qualifier_of(before);
        let qualified_by_child = qualifier.as_deref().is_some_and(child_qualifier);
        let called = empty_parens(next) || opens_turbofish(next);
        if listed(SINK_FNS, &name) || (listed(SINK_METHODS, &name) && qualified_by_child) {
            self.path_sink(name);
        } else if listed(SINK_METHODS, &name) && follows_dot(before) && called {
            self.method_sink(format!("{MACRO_RECEIVER}.{name}"));
        } else if name == "new" && qualified_by_child {
            self.site(MACRO_RECEIVER.to_owned());
        }
    }

    fn mod_file(&mut self, name: &str, child_dir: PathBuf) {
        let flat = self.dir.join(format!("{name}.rs"));
        let nested = child_dir.join("mod.rs");
        let production = self.production;
        match (flat.is_file(), nested.is_file()) {
            (true, false) => self.out.children.push((flat, child_dir, production)),
            (false, true) => self.out.children.push((nested, child_dir, production)),
            (true, true) | (false, false) => {
                self.refuse(&format!("module `{name}` without exactly one file"));
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        let Some(attrs) = item_attrs(item) else {
            if let Item::Verbatim(tokens) = item {
                self.scan_tokens(tokens.clone());
            } else {
                self.refuse("an item shape this scan does not know");
            }
            return;
        };
        self.gated(is_test_only(attrs), |s| match item {
            Item::Fn(f) => s.function(&f.sig, |s| visit::visit_item_fn(s, f)),
            Item::Trait(t) => s.within(name_of(&t.ident), |s| visit::visit_item_trait(s, t)),
            Item::Const(c) => {
                s.constant(&c.ident, &c.ty);
                visit::visit_item_const(s, c);
            }
            Item::Static(st) => {
                s.constant(&st.ident, &st.ty);
                visit::visit_item_static(s, st);
            }
            _ => visit::visit_item(s, item),
        });
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        self.within(impl_name(item), |s| visit::visit_item_impl(s, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        match item {
            ImplItem::Fn(f) => self.gated(is_test_only(&f.attrs), |s| {
                s.function(&f.sig, |s| visit::visit_impl_item_fn(s, f));
            }),
            ImplItem::Const(c) => self.gated(is_test_only(&c.attrs), |s| {
                s.constant(&c.ident, &c.ty);
                visit::visit_impl_item_const(s, c);
            }),
            ImplItem::Type(t) => {
                self.gated(is_test_only(&t.attrs), |s| s.visit_impl_item_type(t));
            }
            ImplItem::Macro(m) => self.gated(is_test_only(&m.attrs), |s| {
                visit::visit_impl_item_macro(s, m);
            }),
            ImplItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            _ => self.refuse("an impl item shape this scan does not know"),
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        match item {
            TraitItem::Fn(f) => self.gated(is_test_only(&f.attrs), |s| {
                s.function(&f.sig, |s| visit::visit_trait_item_fn(s, f));
            }),
            TraitItem::Const(c) => self.gated(is_test_only(&c.attrs), |s| {
                s.constant(&c.ident, &c.ty);
                visit::visit_trait_item_const(s, c);
            }),
            TraitItem::Type(t) => {
                self.gated(is_test_only(&t.attrs), |s| s.visit_trait_item_type(t));
            }
            TraitItem::Macro(m) => self.gated(is_test_only(&m.attrs), |s| {
                visit::visit_trait_item_macro(s, m);
            }),
            TraitItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            _ => self.refuse("a trait item shape this scan does not know"),
        }
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        self.aliasing(|s| visit::visit_item_type(s, item));
    }

    fn visit_impl_item_type(&mut self, item: &'ast ImplItemType) {
        self.aliasing(|s| visit::visit_impl_item_type(s, item));
    }

    fn visit_trait_item_type(&mut self, item: &'ast TraitItemType) {
        self.aliasing(|s| visit::visit_trait_item_type(s, item));
    }

    fn visit_ident(&mut self, ident: &'ast Ident) {
        let name = name_of(ident);
        if self.production && self.in_alias > 0 && listed(CHILD_TYPES, &name) {
            self.refuse(&format!("a type alias naming `{name}`"));
        }
    }

    fn visit_pat_ident(&mut self, pat: &'ast PatIdent) {
        if self.production {
            let key = self.key();
            self.out.bindings.push((key, name_of(&pat.ident)));
        }
        visit::visit_pat_ident(self, pat);
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.attrs.iter().any(names_a_path) {
            self.refuse("a `#[path]` module");
            return;
        }
        let name = name_of(&item.ident);
        let child_dir = self.dir.join(&name);
        if item.content.is_some() {
            let outer = std::mem::replace(&mut self.dir, child_dir);
            self.within(name, |s| visit::visit_item_mod(s, item));
            self.dir = outer;
        } else {
            self.mod_file(&name, child_dir);
        }
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        match tree {
            UseTree::Rename(rename) => {
                let from = name_of(&rename.ident);
                let to = name_of(&rename.rename);
                if self.production && to != "_" {
                    if rename_refused(&from) {
                        self.refuse(&format!("a renaming `use` of `{from}`"));
                    }
                    self.out.renames.push((from, to.clone()));
                    self.import(to);
                }
            }
            UseTree::Name(used) => self.import(name_of(&used.ident)),
            UseTree::Glob(_) => self.import(GLOB_BINDING.to_owned()),
            UseTree::Path(_) | UseTree::Group(_) => visit::visit_use_tree(self, tree),
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Call(call) = expr
            && let Expr::Path(callee) = &*call.func
        {
            if let Some(path) = self.path_of(callee) {
                self.path_call(path, &call.args);
            }
            for arg in &call.args {
                self.visit_expr(arg);
            }
            return;
        }
        match expr {
            Expr::Path(path) => {
                if let Some(path) = self.path_of(path) {
                    self.value_path(&path);
                }
            }
            Expr::MethodCall(call) => self.method_call(call),
            _ => {}
        }
        visit::visit_expr(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac.path.is_ident(INCLUDE_MACRO) {
            self.refuse("an `include!`");
            return;
        }
        let parsed = mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated);
        let Ok(exprs) = parsed else {
            self.scan_tokens(mac.tokens.clone());
            return;
        };
        for expr in &exprs {
            self.visit_expr(expr);
        }
    }
}

/// Scan one parsed file named `file`, reached as production or not, whose
/// `mod x;` declarations resolve in `dir`.
fn scan_file(file: &str, dir: PathBuf, production: bool, syntax: &syn::File) -> FileScan {
    let mut scanner = Scanner {
        dir,
        context: Vec::new(),
        in_alias: 0,
        production: production && !is_test_only(&syntax.attrs),
        file,
        out: FileScan::default(),
    };
    scanner.visit_file(syntax);
    scanner.out
}

/// The `ipe` crate's `src/` directory.
fn src_root() -> PathBuf {
    e2e_support::manifest_dir!().join("src")
}

/// `file` relative to `root`, with `/` separators.
fn relative(root: &Path, file: &Path) -> Result<String, std::path::StripPrefixError> {
    Ok(file
        .strip_prefix(root)?
        .to_string_lossy()
        .replace('\\', "/"))
}

/// Every crate root under `root`, each with the directory its modules resolve in.
fn crate_roots(root: &Path) -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    let mut roots = vec![
        (root.join("lib.rs"), root.to_path_buf()),
        (root.join("main.rs"), root.to_path_buf()),
    ];
    let bin = root.join("bin");
    for entry in std::fs::read_dir(&bin)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            roots.push((path, bin.clone()));
        }
    }
    Ok(roots)
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if depth > MAX_DIR_DEPTH {
        return Err(std::io::Error::other(format!(
            "source tree deeper than {MAX_DIR_DEPTH}: {}",
            dir.display()
        )));
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, depth.saturating_add(1), out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// What the module-tree walk found.
struct Walked {
    /// Every reached file's scan, keyed relative to `src/`.
    scans: Scans,
    /// Every reached file, with whether it was reached as production.
    reached: BTreeMap<String, bool>,
    /// The walk's own refusals.
    refusals: Vec<String>,
}

/// One queued module file: the file, the directory its modules resolve in,
/// its nesting, and whether it is reached as production.
type Queued = (PathBuf, PathBuf, usize, bool);

/// Scan every file reached from `roots`, keyed relative to `root`.
fn walk(root: &Path, roots: Vec<(PathBuf, PathBuf)>) -> Result<Walked, Box<dyn std::error::Error>> {
    let mut scans = Scans::new();
    let mut reached: BTreeMap<String, bool> = BTreeMap::new();
    let mut refusals = Vec::new();
    let mut queue: Vec<Queued> = roots
        .into_iter()
        .map(|(file, dir)| (file, dir, 0, true))
        .collect();
    while let Some((file, dir, depth, production)) = queue.pop() {
        let rel = relative(root, &file)?;
        if reached
            .get(&rel)
            .is_some_and(|seen_as_production| *seen_as_production || !production)
        {
            continue;
        }
        reached.insert(rel.clone(), production);
        if depth > MAX_DEPTH {
            refusals.push(format!("{rel}: module tree deeper than {MAX_DEPTH}"));
            continue;
        }
        let syntax = syn::parse_file(&std::fs::read_to_string(&file)?)?;
        let mut scan = scan_file(&rel, dir, production, &syntax);
        let next = depth.saturating_add(1);
        queue.extend(std::mem::take(&mut scan.children).into_iter().map(
            |(child, child_dir, child_production)| (child, child_dir, next, child_production),
        ));
        scans.insert(rel, scan);
    }
    Ok(Walked {
        scans,
        reached,
        refusals,
    })
}

/// Every file of `files` the walk did not reach, one line each.
fn unreached(reached: &BTreeMap<String, bool>, files: &[String]) -> Vec<String> {
    files
        .iter()
        .filter(|file| !reached.contains_key(*file))
        .map(|file| format!("{file}: a source file no module declaration reaches"))
        .collect()
}

/// One drift key: file, enclosing fn, program or called name.
type Key = (String, String, String);

/// Add one occurrence of `key` to `counts`.
fn bump(counts: &mut BTreeMap<Key, usize>, key: Key, by: usize) {
    let seen = counts.entry(key).or_default();
    *seen = seen.saturating_add(by);
}

/// Every key whose found count differs from its inventory count, one line each.
fn diff(got: &BTreeMap<Key, usize>, want: &BTreeMap<Key, usize>, what: &str) -> Vec<String> {
    let keys: BTreeSet<&Key> = got.keys().chain(want.keys()).collect();
    keys.into_iter()
        .filter_map(|key| {
            let found = got.get(key).copied().unwrap_or(0);
            let listed = want.get(key).copied().unwrap_or(0);
            (found != listed).then(|| {
                format!(
                    "{}: {what} `{}` in `{}` x{found} (inventory: {listed})",
                    key.0, key.2, key.1
                )
            })
        })
        .collect()
}

/// The (file, fn, name) counts of one kind of fact across `scans`.
fn tallied(scans: &Scans, facts: fn(&FileScan) -> &[Named]) -> BTreeMap<Key, usize> {
    let mut counts = BTreeMap::new();
    for (file, scan) in scans {
        for (within, name) in facts(scan) {
            bump(&mut counts, (file.clone(), within.clone(), name.clone()), 1);
        }
    }
    counts
}

/// The (file, fn, name) counts of name rows.
fn listed_names(rows: &[NameRow]) -> BTreeMap<Key, usize> {
    let mut counts = BTreeMap::new();
    for (file, within, name, count) in rows {
        let key = ((*file).to_owned(), (*within).to_owned(), (*name).to_owned());
        bump(&mut counts, key, *count);
    }
    counts
}

/// The names of the ceilings `remote_ingest.rs` declares.
fn ceiling_names(scans: &Scans) -> BTreeSet<&str> {
    scans.get(CEILING_OWNER).map_or_else(BTreeSet::new, |scan| {
        scan.ceilings.iter().map(String::as_str).collect()
    })
}

/// Every name that could stand for another value than the ceiling it spells,
/// one line each: a binding, a const or static other than the ceiling itself,
/// a renaming `use`, or an identifier of a token-matched macro outside
/// `remote_ingest.rs`.
fn shadowed_ceilings(scans: &Scans) -> Vec<String> {
    let ceilings = ceiling_names(scans);
    let is_ceiling = |name: &String| ceilings.contains(name.as_str());
    let mut found = Vec::new();
    for (file, scan) in scans {
        let owner = file == CEILING_OWNER;
        let named = scan
            .bindings
            .iter()
            .filter(|(_, name)| is_ceiling(name))
            .map(|(within, name)| ("a binding", within, name));
        let declared = scan
            .consts
            .iter()
            .filter(|(within, name)| is_ceiling(name) && !(owner && within.is_empty()))
            .map(|(within, name)| ("a const or static", within, name));
        let spliced = scan
            .macro_idents
            .iter()
            .filter(|(_, name)| !owner && is_ceiling(name))
            .map(|(within, name)| ("a token-matched macro identifier", within, name));
        found.extend(
            named
                .chain(declared)
                .chain(spliced)
                .map(|(what, within, name)| {
                    format!("{file}: {what} named as the ceiling `{name}` in `{within}`")
                }),
        );
        found.extend(
            scan.renames
                .iter()
                .filter(|(from, to)| is_ceiling(from) || is_ceiling(to))
                .map(|(from, to)| {
                    format!("{file}: a renaming `use` of `{from}` as `{to}` touches a ceiling")
                }),
        );
    }
    found
}

/// Every refusal and every drift between `scans` and `inventory`, one line each.
fn judge(scans: &Scans, inventory: &Inventory<'_>) -> Vec<String> {
    let mut found: Vec<String> = scans
        .values()
        .flat_map(|scan| scan.refusals.iter().cloned())
        .collect();
    found.extend(shadowed_ceilings(scans));
    let mut sites = BTreeMap::new();
    for (file, within, program, _, count) in inventory.sites {
        let key = (
            (*file).to_owned(),
            (*within).to_owned(),
            (*program).to_owned(),
        );
        bump(&mut sites, key, *count);
    }
    found.extend(diff(
        &tallied(scans, |scan| scan.sites.as_slice()),
        &sites,
        "child site",
    ));
    found.extend(diff(
        &tallied(scans, |scan| scan.path_sinks.as_slice()),
        &listed_names(inventory.bodies),
        "direct child start",
    ));
    found.extend(diff(
        &tallied(scans, |scan| scan.method_sinks.as_slice()),
        &listed_names(inventory.methods),
        "child-start method name",
    ));
    found
}

/// The scanned crate a site proof reads.
struct World<'a> {
    scans: &'a Scans,
    ceilings: BTreeSet<&'a str>,
    bodies: &'a [NameRow],
}

impl<'a> World<'a> {
    fn new(scans: &'a Scans, bodies: &'a [NameRow]) -> Self {
        Self {
            scans,
            ceilings: ceiling_names(scans),
            bodies,
        }
    }

    /// The signature of the one production fn keyed `fun` in `file`.
    fn sig(&self, file: &str, fun: &str) -> Option<&'a FnSig> {
        self.scans.get(file)?.fns.get(fun)?.as_ref()
    }

    /// How many times `fun` of `file` binds `name`: a pattern, a `use`, a
    /// glob `use`, or a token-matched macro identifier.
    fn binds(&self, file: &str, fun: &str, name: &str) -> usize {
        let Some(scan) = self.scans.get(file) else {
            return 0;
        };
        let count = |facts: &[Named]| {
            facts
                .iter()
                .filter(|(within, bound)| within == fun && (bound == name || bound == GLOB_BINDING))
                .count()
        };
        count(scan.bindings.as_slice())
            .saturating_add(count(scan.imports.as_slice()))
            .saturating_add(count(scan.macro_idents.as_slice()))
    }

    /// The production path calls inside `fun` of `file`.
    fn calls_in(&self, file: &str, fun: &str) -> impl Iterator<Item = &'a Call> {
        self.scans
            .get(file)
            .into_iter()
            .flat_map(|scan| scan.calls.iter())
            .filter(move |call| call.within == fun)
    }

    /// Every production call of the fn keyed `fun`, crate-wide, by its last
    /// component; `None` when it has none or is named other than by a call.
    fn callers_of(&self, fun: &str) -> Option<Vec<(&'a str, &'a Call)>> {
        let name = last_component(fun);
        let mut callers = Vec::new();
        for (file, scan) in self.scans {
            let named_otherwise = scan.values.iter().any(|value| value == name)
                || scan.methods.iter().any(|(_, method)| method == name);
            if named_otherwise {
                return None;
            }
            callers.extend(
                scan.calls
                    .iter()
                    .filter(|call| call.callee.last().is_some_and(|last| last == name))
                    .map(|call| (file.as_str(), call)),
            );
        }
        (!callers.is_empty()).then_some(callers)
    }

    /// The fn of `file` a call of `callee` inside `fun` reaches: `Self::g` in
    /// the enclosing inherent impl, or, from a top-level fn binding no `g` and
    /// declaring no inner fn `g`, the top-level fn `g`.
    fn resolve(&self, file: &str, fun: &str, callee: &[String]) -> Option<String> {
        match callee {
            [qualifier, name] if qualifier == "Self" => {
                let (prefix, _) = fun.rsplit_once("::")?;
                (!prefix.contains('<')).then(|| format!("{prefix}::{name}"))
            }
            [name] => {
                let fns = &self.scans.get(file)?.fns;
                let top_level = !fun.contains("::")
                    && self.binds(file, fun, name) == 0
                    && !fns.contains_key(&format!("{fun}::{name}"))
                    && fns.contains_key(name);
                top_level.then(|| name.clone())
            }
            _ => None,
        }
    }
}

/// The argument at `at` of `call`, when it is a path.
fn arg_at(call: &Call, at: usize) -> Option<&[String]> {
    call.args.get(at)?.as_deref()
}

/// Whether `call`'s callee path ends in `name`.
fn calls(call: &Call, name: &str) -> bool {
    call.callee.last().is_some_and(|last| last == name)
}

/// Whether `path` is a path whose last segment is `name`.
fn names(path: Option<&[String]>, name: &str) -> bool {
    path.and_then(<[String]>::last)
        .is_some_and(|last| last == name)
}

/// Whether `path` is exactly the one identifier `ident`.
fn is_ident(path: Option<&[String]>, ident: &str) -> bool {
    matches!(path, Some([only]) if only == ident)
}

/// `Ok` when `holds`, else the broken `rule`.
fn rule(holds: bool, rule: &str) -> Result<(), String> {
    if holds { Ok(()) } else { Err(rule.to_owned()) }
}

/// Whether the ceiling parameter `param` of `fun` receives `ceiling` from every
/// production caller, `fun` taking no receiver.
fn every_caller_passes(
    world: &World<'_>,
    file: &str,
    fun: &str,
    param: &str,
    ceiling: &str,
) -> bool {
    let Some(sig) = world.sig(file, fun) else {
        return false;
    };
    let at = sig
        .params
        .iter()
        .position(|p| p.ceiling && p.name.as_deref() == Some(param));
    let (false, Some(at), 1) = (sig.receiver, at, world.binds(file, fun, param)) else {
        return false;
    };
    world.callers_of(fun).is_some_and(|callers| {
        callers
            .iter()
            .all(|(_, call)| names(arg_at(call, at), ceiling))
    })
}

/// Whether `call` inside `fun` hands `ceiling` to a same-file helper's ceiling
/// parameter that the helper passes straight to `runner`.
fn through_helper(
    world: &World<'_>,
    file: &str,
    fun: &str,
    call: &Call,
    runner: (&str, usize),
    ceiling: &str,
) -> bool {
    let Some(helper) = world.resolve(file, fun, &call.callee) else {
        return false;
    };
    let Some(sig) = world.sig(file, &helper) else {
        return false;
    };
    !sig.receiver
        && sig.params.iter().enumerate().any(|(at, param)| {
            param.ceiling
                && names(arg_at(call, at), ceiling)
                && param.name.as_deref().is_some_and(|name| {
                    world.binds(file, &helper, name) == 1
                        && world.calls_in(file, &helper).any(|inner| {
                            calls(inner, runner.0) && is_ident(arg_at(inner, runner.1), name)
                        })
                })
        })
}

/// Whether `fun` of `file` runs `runner` under the named `ceiling`: passed
/// directly, through a ceiling parameter every caller fills with it, or through
/// one same-file helper.
fn runs_under(
    world: &World<'_>,
    file: &str,
    fun: &str,
    runner: (&str, usize),
    ceiling: &str,
) -> Result<(), String> {
    if !world.ceilings.contains(ceiling) {
        return Err(format!(
            "`{ceiling}` is not a `const` of type `{CEILING_TYPE}` in `{CEILING_OWNER}`"
        ));
    }
    let direct = world
        .calls_in(file, fun)
        .filter(|call| calls(call, runner.0))
        .map(|call| arg_at(call, runner.1))
        .any(|arg| {
            names(arg, ceiling)
                || matches!(arg, Some([param])
                    if every_caller_passes(world, file, fun, param, ceiling))
        });
    let helped = world
        .calls_in(file, fun)
        .any(|call| through_helper(world, file, fun, call, runner, ceiling));
    rule(
        direct || helped,
        &format!(
            "`{fun}` hands `{ceiling}` to `{}` neither directly, nor through a ceiling \
             parameter every caller fills with it, nor through one helper",
            runner.0
        ),
    )
}

/// Whether the evaluated fn `fun` of `file` reaches `runner`.
fn reaches(world: &World<'_>, file: &str, fun: &str, runner: Runner) -> Result<(), String> {
    let any_call = |name: &str| world.calls_in(file, fun).any(|call| calls(call, name));
    match runner {
        Runner::Local(ceiling) => runs_under(world, file, fun, RUN_LOCAL, ceiling),
        Runner::LocalFed(ceiling) => runs_under(world, file, fun, RUN_LOCAL_FED, ceiling),
        Runner::Inherited(role) => rule(
            world.calls_in(file, fun).any(|call| {
                calls(call, RUN_INHERITED)
                    && call
                        .args
                        .iter()
                        .flatten()
                        .any(|arg| ends_with(arg, &[ROLE_TYPE, role]))
            }),
            &format!("`{fun}` calls no `{RUN_INHERITED}` with `{ROLE_TYPE}::{role}`"),
        ),
        Runner::Replace => rule(
            any_call(EXEC_NAMING),
            &format!("`{fun}` calls no `{EXEC_NAMING}`"),
        ),
        Runner::Probe => rule(
            any_call(RUN_PROBE),
            &format!("`{fun}` calls no `{RUN_PROBE}`"),
        ),
        Runner::Body(body) => rule(
            fun == body
                && world
                    .bodies
                    .iter()
                    .any(|(f, within, ..)| *f == file && *within == body),
            &format!("`{fun}` is not the runner body `{body}`"),
        ),
        Runner::Transfer | Runner::Cargo | Runner::Opener => rule(
            false,
            "a located runner is proved by its site, not by a call",
        ),
    }
}

/// The proof of one [`SITES`] row.
fn proof(world: &World<'_>, row: &SiteRow) -> Result<(), String> {
    let (file, within, _, runner, _) = *row;
    match runner {
        Runner::Opener => rule(
            file == "browser.rs" && within == "open_url",
            "an opener runs only in `browser.rs::open_url`",
        ),
        Runner::Cargo => rule(
            file == "cargo_step.rs",
            "a cargo child is built only in `cargo_step.rs`",
        ),
        Runner::Transfer => rule(
            file == CEILING_OWNER && (within.starts_with("Git::") || within.starts_with("Curl::")),
            "a transfer is built only by `Git` or `Curl` in `remote_ingest.rs`",
        ),
        Runner::Local(_)
        | Runner::LocalFed(_)
        | Runner::Inherited(_)
        | Runner::Replace
        | Runner::Probe
        | Runner::Body(_) => {
            let sig = world
                .sig(file, within)
                .ok_or("the site is not inside a production fn")?;
            if !sig.returns_command {
                return reaches(world, file, within, runner);
            }
            let callers = world
                .callers_of(within)
                .ok_or("the builder has no production caller, or is named other than by a call")?;
            callers.iter().try_for_each(|(caller_file, call)| {
                reaches(world, caller_file, &call.within, runner)
            })
        }
    }
}

/// Every row of `inventory` its runner proof does not hold for, one line each.
fn proofs(scans: &Scans, inventory: &Inventory<'_>) -> Vec<String> {
    let world = World::new(scans, inventory.bodies);
    inventory
        .sites
        .iter()
        .filter_map(|row| {
            proof(&world, row).err().map(|why| {
                format!(
                    "{}: `{}` in `{}` as {:?}: {why}",
                    row.0, row.2, row.1, row.3
                )
            })
        })
        .collect()
}

/// Unbounded `ureq` body reads, whitespace removed.
const UNBOUNDED_BODY_READS: &[&str] = &[".into_json(", ".into_string()"];

/// The one bounded body read: a response reader handed straight to `read_capped`.
const READER: &str = ".into_reader()";

/// The only call an `into_reader` may appear as the first argument of.
const CAPPED_CALL: &str = "read_capped(";

/// `source` with every whitespace character removed.
fn flatten(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Whether the `into_reader` ending at `before` is the first argument of `read_capped`.
fn reader_is_capped(before: &str) -> bool {
    let receiver = before.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    receiver.len() < before.len() && receiver.ends_with(CAPPED_CALL)
}

/// Every unbounded `ureq` body read in one flattened source.
fn violations(flat: &str) -> Vec<String> {
    let mut found = Vec::new();
    if flat.contains("ureq") {
        found.extend(
            UNBOUNDED_BODY_READS
                .iter()
                .filter(|needle| flat.contains(*needle))
                .map(|needle| (*needle).to_owned()),
        );
    }
    found.extend(
        flat.match_indices(READER)
            .filter(|(at, _)| !flat.get(..*at).is_some_and(reader_is_capped))
            .map(|_| READER.to_owned()),
    );
    found
}

#[test]
fn every_production_child_site_names_its_runner() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let Walked {
        scans,
        reached,
        refusals,
    } = walk(&root, roots).expect("module tree walkable");
    for file in [
        "remote_ingest.rs",
        "cargo_step.rs",
        "browser.rs",
        "watch.rs",
        "driver/commands.rs",
    ] {
        assert!(
            reached.get(file) == Some(&true),
            "the walk must reach src/{file} as production, or it is walking the wrong tree"
        );
    }
    let mut paths = Vec::new();
    rust_files(&root, 0, &mut paths).expect("source tree listable");
    let files: Vec<String> = paths
        .iter()
        .map(|path| relative(&root, path).expect("listed under the root"))
        .collect();
    let mut found = refusals;
    found.extend(unreached(&reached, &files));
    found.extend(judge(&scans, &INVENTORY));
    assert!(
        found.is_empty(),
        "every production child starts inside a runner body, and every `Command::new` \
         names its runner in SITES:\n{}",
        found.join("\n")
    );
}

#[test]
fn each_row_is_proved_by_its_runner_call() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let walked = walk(&root, roots).expect("module tree walkable");
    let failed = proofs(&walked.scans, &INVENTORY);
    assert!(
        failed.is_empty(),
        "each SITES row must be proved by the runner call it names:\n{}",
        failed.join("\n")
    );
}

#[test]
fn no_ureq_body_read_is_unbounded() {
    let root = src_root();
    let mut paths = Vec::new();
    rust_files(&root, 0, &mut paths).expect("source tree listable");
    let owner = root.join(CEILING_OWNER);
    assert!(
        paths.contains(&owner),
        "the scan must see src/{CEILING_OWNER}, or it is scanning the wrong tree"
    );
    let offenders: Vec<String> = paths
        .iter()
        .filter(|path| **path != owner)
        .flat_map(|path| {
            let source = std::fs::read_to_string(path).expect("source readable");
            violations(&flatten(&source))
                .into_iter()
                .map(move |needle| format!("{}: {needle}", path.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "an HTTP body is read only through remote_ingest::read_capped:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn matcher_refuses_each_bypass() {
    let refused = [
        "use ureq; let v: Value = resp.into_json()?;",
        "use ureq; let s = resp.into_string()?;",
        "let r = resp.into_reader();",
        "read_capped(std::io::empty()).and(resp.into_reader())",
        "read_capped(\n  (resp).into_reader(), 4)",
    ];
    for sample in refused {
        assert!(
            !violations(&flatten(sample)).is_empty(),
            "matcher must refuse: {sample}"
        );
    }
}

#[test]
fn matcher_admits_the_bounded_forms() {
    let admitted = [
        "remote_ingest::read_capped(\n    response.into_reader(),\n    MAX,\n)",
        "Git::isolated(dir).args([\"fetch\"])",
        "use std::process::Command;",
        "let s = value.into_string();",
    ];
    for sample in admitted {
        assert!(
            violations(&flatten(sample)).is_empty(),
            "matcher must admit: {sample}"
        );
    }
}

/// The ceilings of the sample crate: one named ceiling and one const of another type.
const SAMPLE_CEILINGS: &str = "pub const TOOL_QUERY_LIMITS: LocalCeiling = LocalCeiling(L);\n\
                               pub const NOT_A_CEILING: u64 = 1;\n";

/// The sample tool file's one child site.
const SAMPLE_QUERY: &str =
    "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(c, TOOL_QUERY_LIMITS, S); }\n";

/// The sample tool file's one admitted child-start method name.
const SAMPLE_POST: &str = "fn post(r: Response) { let _ = r.status(); }\n";

/// The sample tool file's site row.
const SAMPLE_SITES: &[SiteRow] = &[(
    "tool.rs",
    "query",
    "tool",
    Runner::Local("TOOL_QUERY_LIMITS"),
    1,
)];

/// The sample tool file's method row.
const SAMPLE_METHODS: &[NameRow] = &[("tool.rs", "post", "r.status", 1)];

/// Every refusal, drift and failed proof of `tool` as `tool.rs` beside the
/// sample ceilings, held to `inventory`.
#[allow(clippy::expect_used)] // a sample that does not parse is a broken test input
fn verdict(tool: &str, inventory: &Inventory<'_>) -> Vec<String> {
    let mut scans = Scans::new();
    for (rel, source) in [(CEILING_OWNER, SAMPLE_CEILINGS), ("tool.rs", tool)] {
        let syntax = syn::parse_file(source).expect("sample parses");
        scans.insert(
            rel.to_owned(),
            scan_file(rel, PathBuf::from("/nonexistent"), true, &syntax),
        );
    }
    let mut found = judge(&scans, inventory);
    found.extend(proofs(&scans, inventory));
    found
}

/// The verdict of the sample tool file with `extra` appended, under its own rows.
fn sample_verdict(extra: &str) -> Vec<String> {
    let inventory = Inventory {
        sites: SAMPLE_SITES,
        bodies: &[],
        methods: SAMPLE_METHODS,
    };
    verdict(&format!("{SAMPLE_QUERY}{SAMPLE_POST}{extra}"), &inventory)
}

/// Whether `found` holds a line naming `why`.
fn refused_for(found: &[String], why: &str) -> bool {
    found.iter().any(|line| line.contains(why))
}

#[test]
fn the_sample_alone_passes() {
    let found = sample_verdict("");
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_raw_child_start_is_refused() {
    let refused = [
        "fn f(mut c: Command) { let _ = c.output(); }",
        "fn f(mut c: Command) { let _ = c.status(); }",
        "fn f(mut c: Command) { let _ = c.spawn(); }",
        "fn f(mut c: Command) { let _ = c.exec(); }",
        "fn f(c: Child) { let _ = c.wait_with_output(); }",
        "fn f(mut c: Command) { let _ = Command::output(&mut c); }",
        "fn f(c: Child) { let _ = std::process::Child::wait_with_output(c); }",
        "fn f(mut c: Command) { let _ = <Command as CommandExt>::exec(&mut c); }",
        "fn f() { let run = Command::status; }",
        "fn f(c: Command) { let _ = spawn_hardened(c); }",
        "fn f(c: Command) { let _ = ipe_runtime_rust::system::spawn_detached(c); }",
        "fn f() { let start = spawn_hardened; }",
        "impl Tool { fn f(c: Command) { let _ = exec_naming(c, NamedFds::default()); } }",
        "#[cfg(any(test, unix))] fn f(mut c: Command) { let _ = c.output(); }",
        "#[cfg(not(test))] fn f(mut c: Command) { let _ = c.output(); }",
        "fn f(mut c: Command) { #[cfg(test)] let _ = c.output(); }",
        "fn f(r: Response) { let _ = r.status(); }",
        "fn post(r: Response) { let _ = r.status(); }",
    ];
    for sample in refused {
        assert!(
            !sample_verdict(sample).is_empty(),
            "the scan must refuse: {sample}"
        );
    }
}

#[test]
fn a_child_start_inside_a_macro_is_refused() {
    let refused = [
        "fn f(mut c: Command) { let _ = format!(\"ran\", c.output()); }",
        "fn f(mut c: Command) { let _ = vec![c.spawn()]; }",
        "fn f(mut c: Command) { let _ = vec![c.spawn(); 2]; }",
        "fn f(c: Command) { m! { let _ = spawn_hardened(c); } }",
        "fn f() { m! { let c = Command::new(\"rustc\"); } }",
        "fn f() { let _ = vec![Command::new(\"rustc\")]; }",
    ];
    for sample in refused {
        assert!(
            !sample_verdict(sample).is_empty(),
            "the scan must refuse: {sample}"
        );
    }
}

#[test]
fn a_hidden_or_renamed_child_start_is_refused() {
    let refused = [
        "use std::process::Command as Spawn;",
        "use std::process::{Command as Spawn, Stdio};",
        "use std::os::unix::process::CommandExt as Ext;",
        "use crate::remote_ingest::run_local as run;",
        "use ipe_runtime_rust::system::spawn_hardened as start;",
        "type Spawn = std::process::Command;",
        "impl Tr for X { type C = Child; }",
        "fn f() { let new = Command::new; }",
        "include!(\"elsewhere.rs\");",
        "fn f() { include!(\"elsewhere.rs\"); }",
        "#[path = \"x.rs\"] mod x;",
        "mod absent_module;",
    ];
    for sample in refused {
        assert!(
            !sample_verdict(sample).is_empty(),
            "the scan must refuse: {sample}"
        );
    }
}

#[test]
fn a_site_without_its_row_or_a_row_without_its_site_is_refused() {
    let unlisted =
        "fn other() { let c = Command::new(\"rustc\"); run_local(c, TOOL_QUERY_LIMITS, S); }";
    assert!(!sample_verdict(unlisted).is_empty(), "{unlisted}");
    let stale_site: &[SiteRow] = &[
        (
            "tool.rs",
            "query",
            "tool",
            Runner::Local("TOOL_QUERY_LIMITS"),
            1,
        ),
        (
            "tool.rs",
            "gone",
            "tool",
            Runner::Local("TOOL_QUERY_LIMITS"),
            1,
        ),
    ];
    let stale_method: &[NameRow] = &[
        ("tool.rs", "post", "r.status", 1),
        ("tool.rs", "gone", "r.status", 1),
    ];
    let stale_body: &[NameRow] = &[("tool.rs", "gone", "spawn_hardened", 1)];
    let inventories = [
        Inventory {
            sites: stale_site,
            bodies: &[],
            methods: SAMPLE_METHODS,
        },
        Inventory {
            sites: SAMPLE_SITES,
            bodies: &[],
            methods: stale_method,
        },
        Inventory {
            sites: SAMPLE_SITES,
            bodies: stale_body,
            methods: SAMPLE_METHODS,
        },
        Inventory {
            sites: &[],
            bodies: &[],
            methods: SAMPLE_METHODS,
        },
    ];
    let sample = format!("{SAMPLE_QUERY}{SAMPLE_POST}");
    for inventory in &inventories {
        assert!(
            !verdict(&sample, inventory).is_empty(),
            "a stale or missing row must be refused"
        );
    }
}

/// A one-site tool file whose `query` site is proved as `runner`.
fn one_site(
    source: &str,
    within: &'static str,
    program: &'static str,
    runner: Runner,
) -> Vec<String> {
    let sites = [("tool.rs", within, program, runner, 1)];
    let inventory = Inventory {
        sites: &sites,
        bodies: &[],
        methods: &[],
    };
    verdict(source, &inventory)
}

#[test]
fn a_ceiling_the_proof_cannot_name_is_refused() {
    let local = Runner::Local("TOOL_QUERY_LIMITS");
    let refused = [
        // Through two hops: `middle` forwards its own parameter.
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn middle(tool: &OsStr, ceiling: LocalCeiling) { query(tool, ceiling); }\n\
             fn outer(tool: &OsStr) { middle(tool, TOOL_QUERY_LIMITS); }",
            local,
        ),
        // One caller passes another ceiling.
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn a(t: &OsStr) { query(t, TOOL_QUERY_LIMITS); }\n\
             fn b(t: &OsStr, other: LocalCeiling) { query(t, other); }",
            local,
        ),
        // The parameter is not a ceiling, or is named other than by a call.
        (
            "fn query(tool: &OsStr, ceiling: Limits) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn a(t: &OsStr) { query(t, TOOL_QUERY_LIMITS); }",
            local,
        ),
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn a(t: &OsStr) { query(t, TOOL_QUERY_LIMITS); let g = query; }",
            local,
        ),
        // A const not of type `LocalCeiling`, and a ceiling the row does not name.
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(c, NOT_A_CEILING, S); }",
            Runner::Local("NOT_A_CEILING"),
        ),
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(c, NOT_A_CEILING, S); }",
            local,
        ),
        // The ceiling in another argument position, or another runner.
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(TOOL_QUERY_LIMITS, c, S); }",
            local,
        ),
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(c, TOOL_QUERY_LIMITS, S); }",
            Runner::LocalFed("TOOL_QUERY_LIMITS"),
        ),
        // A helper that does not pass its ceiling straight to the runner.
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); helper(c, TOOL_QUERY_LIMITS); }\n\
             fn helper(c: Command, ceiling: LocalCeiling) { relay(c, ceiling); }\n\
             fn relay(c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); }",
            local,
        ),
    ];
    for (source, runner) in refused {
        assert!(
            !one_site(source, "query", "tool", runner).is_empty(),
            "the proof must refuse: {source}"
        );
    }
}

#[test]
fn a_row_naming_the_wrong_runner_is_refused() {
    let site = "fn query(tool: &OsStr) { let c = Command::new(tool); run_local(c, TOOL_QUERY_LIMITS, S); }";
    for runner in [
        Runner::Inherited("UserProgram"),
        Runner::Replace,
        Runner::Probe,
        Runner::Opener,
        Runner::Cargo,
        Runner::Transfer,
        Runner::Body("query"),
    ] {
        assert!(
            !one_site(site, "query", "tool", runner).is_empty(),
            "a {runner:?} row must be refused for a `run_local` site"
        );
    }
    let inherited = "fn run(p: &Path) { let c = Command::new(p); run_inherited(c, InheritedRole::SelfBuild, I); }";
    assert!(
        !one_site(inherited, "run", "p", Runner::Inherited("UserProgram")).is_empty(),
        "another role must be refused"
    );
    let outside = "fn build(p: &Path) -> Command { Command::new(p) }";
    assert!(
        !one_site(outside, "build", "p", Runner::Body("start")).is_empty(),
        "a builder nobody calls must be refused"
    );
}

#[test]
fn the_bounded_forms_are_admitted() {
    let local = Runner::Local("TOOL_QUERY_LIMITS");
    let admitted = [
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn outer(t: &OsStr) { query(t, crate::remote_ingest::TOOL_QUERY_LIMITS); }",
            "query",
            "tool",
            local,
        ),
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); helper(c, TOOL_QUERY_LIMITS); }\n\
             fn helper(c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); }",
            "query",
            "tool",
            local,
        ),
        (
            "impl Tool { fn active() { let _ = Self::query(Command::new(\"rustc\"), TOOL_QUERY_LIMITS); }\n\
             fn query(mut c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); } }",
            "Tool::active",
            "\"rustc\"",
            local,
        ),
        (
            "fn probe(stdin: B) { let c = Command::new(\"rustc\"); run_local_fed(c, stdin, TOOL_QUERY_LIMITS, S); }",
            "probe",
            "\"rustc\"",
            Runner::LocalFed("TOOL_QUERY_LIMITS"),
        ),
        (
            "fn run(p: &Path) { let c = Command::new(p); run_inherited(c, InheritedRole::UserProgram, I); }",
            "run",
            "p",
            Runner::Inherited("UserProgram"),
        ),
    ];
    for (source, within, program, runner) in admitted {
        let found = one_site(source, within, program, runner);
        assert!(found.is_empty(), "{source}: {found:?}");
    }
    let replaced = "fn run(p: &Path) { let c = Command::new(&p.bin); let _ = exec_naming(c, N); }";
    let sites = [("tool.rs", "run", "&p.bin", Runner::Replace, 1)];
    let bodies = [("tool.rs", "run", "exec_naming", 1)];
    let inventory = Inventory {
        sites: &sites,
        bodies: &bodies,
        methods: &[],
    };
    let found = verdict(replaced, &inventory);
    assert!(found.is_empty(), "{replaced}: {found:?}");
}

#[test]
fn a_builder_is_proved_through_its_caller() {
    let source = "fn build(p: &Path) -> Command { Command::new(p) }\n\
                  fn start(p: &Path) { let _ = spawn_hardened(build(p)); }";
    let sites = [("tool.rs", "build", "p", Runner::Body("start"), 1)];
    let bodies = [("tool.rs", "start", "spawn_hardened", 1)];
    let inventory = Inventory {
        sites: &sites,
        bodies: &bodies,
        methods: &[],
    };
    let found = verdict(source, &inventory);
    assert!(found.is_empty(), "{found:?}");
    let named = format!("{source}\nfn other() {{ let b = build; }}");
    assert!(
        !verdict(&named, &inventory).is_empty(),
        "a builder named other than by a call must be refused"
    );
}

#[test]
fn test_code_and_the_admitted_imports_are_not_sites() {
    let admitted = [
        "#[cfg(test)] mod tests { fn t() { let _ = Command::new(\"x\").output(); } }",
        "#[cfg(test)] fn helper(mut c: Command) { let _ = c.spawn(); }",
        "#[cfg(all(test, unix))] fn helper(mut c: Command) { let _ = c.status(); }",
        "#[cfg(any(test, all(test, unix)))] fn helper(c: Command) { let _ = spawn_hardened(c); }",
        "impl Tool { #[cfg(test)] fn at(p: &Path) -> Command { Command::new(p) } }",
        "use std::os::unix::process::CommandExt as _;",
        "use std::process::{Command, Stdio};",
        "use ipe_runtime_rust::system::spawn_hardened;",
        "fn f(c: &Captured) -> bool { c.status.success() }",
        "fn f(mut c: Command) { let _ = c.arg(\"x\").output_dir(); }",
        "fn f() { let _ = \"Command::new(x).output()\"; }",
        "/// See `Command::new(x).output()`.\nfn documented() { let _ = 1; }",
    ];
    for sample in admitted {
        let found = sample_verdict(sample);
        assert!(found.is_empty(), "{sample}: {found:?}");
    }
}

#[test]
fn a_qualified_self_type_is_read_as_its_path() {
    let refused = [
        (
            "fn f(mut c: Command) { let _ = <Command>::output(&mut c); }",
            "direct child start `output`",
        ),
        (
            "fn f(mut c: Command) { let _ = <(Command)>::output(&mut c); }",
            "direct child start `output`",
        ),
        (
            "fn f(mut c: Command) { let _ = <&Command>::status(&mut c); }",
            "direct child start `status`",
        ),
        (
            "fn f() { let c = <Command>::new(\"x\"); }",
            "child site `\"x\"`",
        ),
        (
            "fn f() { let _ = <[u8]>::len(&[]); }",
            "a qualified path whose self type",
        ),
        (
            "fn f(mut c: Command) { m! { let _ = <Command>::output(&mut c); } }",
            "direct child start `output`",
        ),
        (
            "fn f(mut c: Command) { m! { let _ = <Command as Ext<X>>::exec(&mut c); } }",
            "direct child start `exec`",
        ),
    ];
    for (sample, why) in refused {
        let found = sample_verdict(sample);
        assert!(refused_for(&found, why), "{sample}: {found:?}");
    }
}

#[test]
fn a_raw_identifier_is_read_as_its_name() {
    let refused = [
        (
            "fn f(mut c: Command) { let _ = c.r#output(); }",
            "method name `c.output`",
        ),
        (
            "fn f(c: Command) { let _ = r#spawn_hardened(c); }",
            "direct child start `spawn_hardened`",
        ),
        (
            "fn f() { let c = r#Command::r#new(\"x\"); }",
            "child site `\"x\"`",
        ),
        (
            "fn f(mut c: Command) { m! { let _ = c.r#output(); } }",
            "method name `<macro>.output`",
        ),
    ];
    for (sample, why) in refused {
        let found = sample_verdict(sample);
        assert!(refused_for(&found, why), "{sample}: {found:?}");
    }
}

#[test]
fn a_child_start_a_macro_splices_together_is_refused() {
    let refused = [
        (
            "macro_rules! call { ($c:expr, $m:ident) => { $c.$m() }; }\n\
             fn f(mut c: Command) { call!(c, output); }",
            "a method or child-type path segment a macro metavariable supplies",
        ),
        (
            "macro_rules! call { ($m:ident, $c:expr) => { Command::$m(&mut $c) }; }\n\
             fn f(mut c: Command) { call!(output, c); }",
            "a method or child-type path segment a macro metavariable supplies",
        ),
        (
            "macro_rules! call { ($t:ident, $c:expr) => { $t::output(&mut $c) }; }\n\
             fn f(mut c: Command) { call!(Command, c); }",
            "direct child start `output`",
        ),
        (
            "fn f(mut c: Command) { m! { let _ = c.output::<>(); } }",
            "method name `<macro>.output`",
        ),
    ];
    for (sample, why) in refused {
        let found = sample_verdict(sample);
        assert!(refused_for(&found, why), "{sample}: {found:?}");
    }
}

#[test]
fn a_local_fn_named_as_a_runner_is_refused() {
    let refused = [
        "fn run_local(c: Command, l: LocalCeiling, s: S) { run_inherited(c, InheritedRole::UserProgram, I); }",
        "impl Tool { fn run_local(c: Command, l: LocalCeiling, s: S) { let _ = (c, l, s); } }",
        "fn spawn_detached(c: Command) { let _ = c; }",
    ];
    for sample in refused {
        let found = sample_verdict(sample);
        assert!(
            refused_for(&found, "a fn named as a runner or sink fn"),
            "{sample}: {found:?}"
        );
    }
}

#[test]
fn a_rebound_ceiling_name_is_refused() {
    let refused = [
        (
            "use crate::remote_ingest::SELF_RUN_LIMITS as TOOL_QUERY_LIMITS;",
            "touches a ceiling",
        ),
        (
            "use crate::remote_ingest::LocalCeiling as C;",
            "a renaming `use` of `LocalCeiling`",
        ),
        (
            "const TOOL_QUERY_LIMITS: LocalCeiling = LocalCeiling(WIDE);",
            "outside the top level of `remote_ingest.rs`",
        ),
        (
            "impl Tool { const TOOL_QUERY_LIMITS: LocalCeiling = LocalCeiling(WIDE); }",
            "outside the top level of `remote_ingest.rs`",
        ),
        (
            "const TOOL_QUERY_LIMITS: Wide = WIDE;",
            "a const or static named as the ceiling",
        ),
        (
            "static TOOL_QUERY_LIMITS: Wide = WIDE;",
            "a const or static named as the ceiling",
        ),
        (
            "macro_rules! wide { () => { const TOOL_QUERY_LIMITS: L = W; }; }",
            "a token-matched macro identifier named as the ceiling",
        ),
        (
            "fn f(TOOL_QUERY_LIMITS: Wide) { let _ = TOOL_QUERY_LIMITS; }",
            "a binding named as the ceiling",
        ),
    ];
    for (sample, why) in refused {
        let found = sample_verdict(sample);
        assert!(refused_for(&found, why), "{sample}: {found:?}");
    }
    let shadowed = "fn query(tool: &OsStr) { let TOOL_QUERY_LIMITS = wider(); let c = Command::new(tool); run_local(c, TOOL_QUERY_LIMITS, S); }";
    let found = one_site(
        shadowed,
        "query",
        "tool",
        Runner::Local("TOOL_QUERY_LIMITS"),
    );
    assert!(
        refused_for(&found, "a binding named as the ceiling"),
        "{found:?}"
    );
}

#[test]
fn a_proof_through_a_rebound_or_unresolved_name_is_refused() {
    let local = Runner::Local("TOOL_QUERY_LIMITS");
    let one_hop = "neither directly, nor through a ceiling parameter";
    let refused = [
        // The ceiling parameter is rebound before it reaches the runner.
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let ceiling = widen(ceiling); let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn a(t: &OsStr) { query(t, TOOL_QUERY_LIMITS); }",
            "query",
        ),
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); helper(c, TOOL_QUERY_LIMITS); }\n\
             fn helper(c: Command, ceiling: LocalCeiling) { let ceiling = widen(ceiling); run_local(c, ceiling, S); }",
            "query",
        ),
        // A caller hidden in a macro the expression parse does not read.
        (
            "fn query(tool: &OsStr, ceiling: LocalCeiling) { let c = Command::new(tool); run_local(c, ceiling, S); }\n\
             fn a(t: &OsStr) { query(t, TOOL_QUERY_LIMITS); }\n\
             fn b(t: &OsStr) { m! { let _ = query(t, WIDE); } }",
            "query",
        ),
        // A bare call that reaches no top-level fn of the file.
        (
            "fn query(tool: &OsStr) { let c = Command::new(tool); helper(c, TOOL_QUERY_LIMITS); }\n\
             impl Tool { fn helper(c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); } }",
            "query",
        ),
        (
            "fn query(tool: &OsStr) { use other::helper; let c = Command::new(tool); helper(c, TOOL_QUERY_LIMITS); }\n\
             fn helper(c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); }",
            "query",
        ),
        // `Self::` in a trait impl reaches an inherent fn first.
        (
            "impl Run for Tool { fn query() { let _ = Self::helper(Command::new(\"rustc\"), TOOL_QUERY_LIMITS); }\n\
             fn helper(c: Command, ceiling: LocalCeiling) { run_local(c, ceiling, S); } }\n\
             impl Tool { fn helper(c: Command, ceiling: LocalCeiling) { run_local(c, wider(), S); } }",
            "<Tool as Run>::query",
        ),
    ];
    for (source, within) in refused {
        let program = if within == "query" {
            "tool"
        } else {
            "\"rustc\""
        };
        let found = one_site(source, within, program, local);
        assert!(refused_for(&found, one_hop), "{source}: {found:?}");
    }
}

#[test]
fn two_fns_under_one_key_are_refused() {
    let source = "impl Tool<A> { fn build(p: &Path) -> Command { Command::new(p) } }\n\
                  impl Tool<B> { fn build(p: &Path) { let _ = exec_naming(make(p), N); } }";
    let sites = [("tool.rs", "Tool::build", "p", Runner::Replace, 1)];
    let bodies = [("tool.rs", "Tool::build", "exec_naming", 1)];
    let inventory = Inventory {
        sites: &sites,
        bodies: &bodies,
        methods: &[],
    };
    let found = verdict(source, &inventory);
    assert!(
        refused_for(&found, "the site is not inside a production fn"),
        "{found:?}"
    );
}

#[test]
fn an_admitted_method_name_is_held_to_its_receiver() {
    let inventory = Inventory {
        sites: SAMPLE_SITES,
        bodies: &[],
        methods: SAMPLE_METHODS,
    };
    let found = verdict(
        &format!("{SAMPLE_QUERY}fn post(c: Command) {{ let _ = c.status(); }}\n"),
        &inventory,
    );
    assert!(refused_for(&found, "method name `c.status`"), "{found:?}");
}

#[test]
fn a_test_only_file_is_scanned_as_test_code() {
    let syntax = syn::parse_file("#![cfg(test)]\nfn t(mut c: Command) { let _ = c.output(); }")
        .expect("sample parses");
    let scan = scan_file("tests.rs", PathBuf::from("/nonexistent"), true, &syntax);
    assert!(scan.method_sinks.is_empty() && scan.refusals.is_empty());
    let syntax =
        syn::parse_file("fn t(mut c: Command) { let _ = c.output(); }").expect("sample parses");
    let scan = scan_file("tests.rs", PathBuf::from("/nonexistent"), false, &syntax);
    assert!(scan.method_sinks.is_empty() && scan.refusals.is_empty());
}

#[test]
fn an_unreached_file_is_refused() {
    let reached: BTreeMap<String, bool> = std::iter::once(("lib.rs".to_owned(), true)).collect();
    let hidden = ["lib.rs".to_owned(), "hidden.rs".to_owned()];
    assert!(!unreached(&reached, &hidden).is_empty());
    assert!(unreached(&reached, &["lib.rs".to_owned()]).is_empty());
}

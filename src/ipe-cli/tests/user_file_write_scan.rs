#![forbid(unsafe_code)]
//! Proves no production code of the `ipe` crate rewrites a file by path.
//!
//! A user file is rewritten only through the held writer
//! (`output_dir::held::HeldDir`), which judges and replaces it on one held
//! parent with a re-proved identity. Every other filesystem write the crate's
//! own source (`src/ipe-cli/src`) makes must name its enclosing fn in
//! [`SITES`] with the class of what it writes; a write with no row, and a row
//! with no write, are refused.
//!
//! The scan walks the crate's module tree from each crate root, parsing every
//! reached file with `syn`. An item, impl item or trait item marked `#[test]`,
//! or whose `cfg` is `test`, an `all(..)` holding `test`, or an `any(..)` of
//! test-only predicates, is test code; every other `cfg` is production. A
//! source file the walk never reaches, a `#[path]` module and an `include!`
//! are refused, since each would hide source.
//!
//! In production code a write is any of:
//!
//! - a path ending `fs::f` for an `f` in [`FS_FNS`], called or not;
//! - a qualified path ending in a [`CREATE_FNS`] name, whatever its qualifier,
//!   so a `File` reached through an alias is still seen;
//! - a method call of `create_new` or `set_permissions`, whatever its receiver;
//! - a method call of an [`OPEN_FLAGS`] name whose one argument is `true`.
//!
//! An identifier named as a by-path rewriter ([`BANNED`], or one starting with
//! `rewrite_user_file`), a `use` importing an [`FS_FNS`] name from `fs`, a glob
//! `use` of `fs`, and a renaming `use` of `fs`, an [`FS_FNS`] name or a banned
//! name are refused outright. A macro body is read as comma-separated
//! expressions, or else token by token under the same rules.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Ident, TokenStream, TokenTree};
use syn::ext::IdentExt as _;
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprMethodCall, ExprPath, ImplItem, Item, ItemImpl, ItemMod, ItemUse, Lit,
    Macro, Meta, Token, TraitItem, Type, UseTree,
};

/// What an allowlisted write writes.
#[derive(Clone, Copy, Debug)]
enum SiteClass {
    /// ipe-owned state under an ipe-owned root.
    ///
    /// A cache, a scratch tree, the target dir, the credential store.
    Cache,
    /// Output ipe generates under a root it owns.
    ///
    /// An emitted crate, a built binary, a generated doc.
    Generated,
    /// A fresh file or directory created exclusively, never an existing one.
    NewFile,
    /// The held writer itself, through which every user file is rewritten.
    Writer,
}

/// One allowlist row: file relative to `src/`, enclosing fn key, class.
type Site = (&'static str, &'static str, SiteClass);

/// Every production fn that writes the filesystem, with what it writes.
///
/// A fn key is the enclosing inline modules, impl self type, trait and fns,
/// joined by `::`. No row admits a user file: those go through the held writer.
const SITES: &[Site] = &[
    ("audit.rs", "derive_deny_config", SiteClass::Generated),
    (
        "audit_native.rs",
        "JailProbeRunner::run",
        SiteClass::NewFile,
    ),
    (
        "audit_native.rs",
        "StagedWrapper::create_at",
        SiteClass::NewFile,
    ),
    (
        "audit_native.rs",
        "StagedWrapper::drop",
        SiteClass::Generated,
    ),
    (
        "audit_native.rs",
        "emit_probe_and_build_argv",
        SiteClass::Generated,
    ),
    ("bin/gen_cli_docs.rs", "run", SiteClass::Generated),
    ("cache.rs", "create_salt", SiteClass::NewFile),
    ("driver/commands.rs", "set_executable", SiteClass::Generated),
    (
        "driver/commands_pkg.rs",
        "build_and_run_test_entry",
        SiteClass::Cache,
    ),
    (
        "driver/commands_pkg.rs",
        "download_installer",
        SiteClass::NewFile,
    ),
    (
        "driver/commands_pkg.rs",
        "run_installer",
        SiteClass::NewFile,
    ),
    (
        "driver/commands_pkg.rs",
        "store_test_lock",
        SiteClass::Cache,
    ),
    ("ffi.rs", "write_inspector_manifest", SiteClass::Cache),
    ("ffi.rs", "write_inspector_manifest_chunk", SiteClass::Cache),
    ("login.rs", "logout_at", SiteClass::Cache),
    (
        "lsp.rs",
        "stdlib_cache::StdlibCache::open",
        SiteClass::Cache,
    ),
    ("lsp.rs", "stdlib_cache::fill_read_only", SiteClass::Cache),
    (
        "output_dir/held.rs",
        "HeldDir::create_if_absent",
        SiteClass::Writer,
    ),
    (
        "output_dir/held.rs",
        "HeldDir::publish_marker",
        SiteClass::Writer,
    ),
    (
        "output_dir/held.rs",
        "HeldDir::replace_file",
        SiteClass::Writer,
    ),
    ("output_dir/held/unix.rs", "carry_mode", SiteClass::Writer),
    (
        "output_dir/held/windows.rs",
        "claim_options",
        SiteClass::Writer,
    ),
    (
        "output_dir/held/windows.rs",
        "create_claim",
        SiteClass::Writer,
    ),
    (
        "output_dir/held/windows.rs",
        "create_new",
        SiteClass::Writer,
    ),
    (
        "output_dir/held/windows.rs",
        "is_held_pin",
        SiteClass::Writer,
    ),
    ("output_dir/held/windows.rs", "pin", SiteClass::Writer),
    ("output_dir/held/windows.rs", "rename", SiteClass::Writer),
    (
        "output_dir/held/windows.rs",
        "rename_noreplace",
        SiteClass::Writer,
    ),
    ("project_root/tree.rs", "write_file", SiteClass::NewFile),
    ("publish.rs", "run_curl_on", SiteClass::NewFile),
    (
        "secret_file.rs",
        "OwnerDir::create_temp_for",
        SiteClass::NewFile,
    ),
    ("secret_file.rs", "create_owner_dir", SiteClass::NewFile),
    ("target_dir.rs", "drop_shared_write", SiteClass::Cache),
    ("target_dir.rs", "open_no_follow", SiteClass::Cache),
    ("target_dir.rs", "remove_locked_dir", SiteClass::Cache),
];

/// The `std::fs` functions that write, rename, copy, link or remove by path.
const FS_FNS: &[&str] = &[
    "write",
    "copy",
    "rename",
    "remove_file",
    "set_permissions",
    "hard_link",
    "symlink",
    "symlink_file",
    "symlink_dir",
];

/// Associated fns that create a file, whatever type they are reached through.
const CREATE_FNS: &[&str] = &["create", "create_new"];

/// Methods that write through a handle or a held directory, whatever the receiver.
const HANDLE_WRITES: &[&str] = &["create_new", "set_permissions"];

/// `OpenOptions` builder flags that open a file for writing.
const OPEN_FLAGS: &[&str] = &["write", "append", "truncate", "create"];

/// The names of the by-path rewriters the held writer replaced.
const BANNED: &[&str] = &["write_atomic", "backup_user_file", "numbered_backup"];

/// The prefix of every by-path rewriter name.
const BANNED_PREFIX: &str = "rewrite_user_file";

/// The macro that splices a file into the module tree.
const INCLUDE_MACRO: &str = "include";

/// The deepest module nesting the walk follows.
const MAX_DEPTH: usize = 64;

/// The deepest directory nesting the file listing follows.
const MAX_DIR_DEPTH: usize = 64;

/// An identifier's name, any `r#` prefix removed.
fn name_of(ident: &Ident) -> String {
    ident.unraw().to_string()
}

/// Whether `name` is a by-path rewriter name.
fn banned(name: &str) -> bool {
    BANNED.contains(&name) || name.starts_with(BANNED_PREFIX)
}

/// Whether a renaming `use` of `name` would hide a write from the scan.
fn rename_refused(name: &str) -> bool {
    name == "fs" || FS_FNS.contains(&name) || banned(name)
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

/// Whether `attrs` make the item test code: a `#[test]`, or a test-only `cfg`.
fn is_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .meta
                    .require_list()
                    .ok()
                    .and_then(|list| syn::parse2::<Meta>(list.tokens.clone()).ok())
                    .is_some_and(|meta| test_only(&meta)))
    })
}

/// Whether `attr` is a `#[path]`, or a `#[cfg_attr]` that may expand to one.
fn names_a_path(attr: &Attribute) -> bool {
    attr.path().is_ident("path")
        || (attr.path().is_ident("cfg_attr")
            && attr
                .meta
                .require_list()
                .is_ok_and(|list| tokens_name_path(list.tokens.clone())))
}

/// Whether `tokens`, nested groups included, hold a `path` identifier.
fn tokens_name_path(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => name_of(&ident) == "path",
        TokenTree::Group(group) => tokens_name_path(group.stream()),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// The attributes of `item`, or `None` for a shape this scan does not read.
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

/// The attributes of an impl item, or `None` for a shape this scan does not read.
fn impl_item_attrs(item: &ImplItem) -> Option<&[Attribute]> {
    let attrs: &[Attribute] = match item {
        ImplItem::Const(i) => &i.attrs,
        ImplItem::Fn(i) => &i.attrs,
        ImplItem::Type(i) => &i.attrs,
        ImplItem::Macro(i) => &i.attrs,
        _ => return None,
    };
    Some(attrs)
}

/// The attributes of a trait item, or `None` for a shape this scan does not read.
fn trait_item_attrs(item: &TraitItem) -> Option<&[Attribute]> {
    let attrs: &[Attribute] = match item {
        TraitItem::Const(i) => &i.attrs,
        TraitItem::Fn(i) => &i.attrs,
        TraitItem::Type(i) => &i.attrs,
        TraitItem::Macro(i) => &i.attrs,
        _ => return None,
    };
    Some(attrs)
}

/// The name a type is keyed by: its last path segment, behind any reference.
fn type_name(ty: &Type) -> String {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map_or_else(|| "_".to_owned(), |segment| name_of(&segment.ident)),
        Type::Reference(reference) => type_name(&reference.elem),
        _ => "_".to_owned(),
    }
}

/// The name of an impl's self type.
fn impl_name(item: &ItemImpl) -> String {
    type_name(&item.self_ty)
}

/// The write a path names, if any.
///
/// That is `fs::f` for an [`FS_FNS`] name, or a qualified [`CREATE_FNS`] name.
fn path_write(segments: &[String], qualified: bool) -> Option<String> {
    let (last, before) = segments.split_last()?;
    let parent = before.last();
    if FS_FNS.contains(&last.as_str()) && parent.is_some_and(|p| p == "fs") {
        return Some(format!("fs::{last}"));
    }
    (CREATE_FNS.contains(&last.as_str()) && (qualified || parent.is_some()))
        .then(|| format!("::{last}"))
}

/// One flattened token of a macro body, at one nesting level.
enum Tok {
    /// An identifier, by name.
    Name(String),
    /// A punctuation character.
    Punct(char),
    /// A delimited group.
    Group(Delimiter, TokenStream),
    /// A literal.
    Literal,
}

/// The tokens of `tokens` at its top level.
fn flatten(tokens: TokenStream) -> Vec<Tok> {
    tokens
        .into_iter()
        .map(|tree| match tree {
            TokenTree::Ident(ident) => Tok::Name(name_of(&ident)),
            TokenTree::Punct(punct) => Tok::Punct(punct.as_char()),
            TokenTree::Group(group) => Tok::Group(group.delimiter(), group.stream()),
            TokenTree::Literal(_) => Tok::Literal,
        })
        .collect()
}

/// Whether `stream` is the single token `true`.
fn is_true(stream: &TokenStream) -> bool {
    let mut trees = stream.clone().into_iter();
    matches!(
        (trees.next(), trees.next()),
        (Some(TokenTree::Ident(ident)), None) if ident == "true"
    )
}

/// Whether the call's arguments are the single literal `true`.
fn args_are_true(args: &Punctuated<Expr, Token![,]>) -> bool {
    args.len() == 1
        && args.first().is_some_and(|arg| {
            matches!(arg, Expr::Lit(lit) if matches!(&lit.lit, Lit::Bool(flag) if flag.value))
        })
}

/// What one file's scan found.
#[derive(Default)]
struct FileScan {
    /// Every production write: enclosing fn key and what it calls.
    hits: Vec<(String, String)>,
    /// Every refusal, one line each.
    refusals: Vec<String>,
    /// Every `mod x;` file, its module directory, and whether it is production.
    children: Vec<(PathBuf, PathBuf, bool)>,
}

/// The syntax visitor for one file.
struct Scanner<'a> {
    /// The directory `mod x;` declarations at the current nesting resolve in.
    dir: PathBuf,
    /// The enclosing item path.
    context: Vec<String>,
    /// Whether the current node is production code.
    production: bool,
    /// The file's name relative to `src/`, for refusals.
    file: &'a str,
    out: FileScan,
}

impl Scanner<'_> {
    fn key(&self) -> String {
        self.context.join("::")
    }

    fn refuse(&mut self, what: &str) {
        if self.production {
            let key = self.key();
            self.out
                .refusals
                .push(format!("{}: {what} in `{key}`", self.file));
        }
    }

    fn hit(&mut self, what: String) {
        if self.production {
            let key = self.key();
            self.out.hits.push((key, what));
        }
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

    fn mod_file(&mut self, name: &str, child_dir: PathBuf) {
        let flat = self.dir.join(format!("{name}.rs"));
        let nested = child_dir.join("mod.rs");
        let production = self.production;
        match (flat.is_file(), nested.is_file()) {
            (true, false) => self.out.children.push((flat, child_dir, production)),
            (false, true) => self.out.children.push((nested, child_dir, production)),
            (true, true) | (false, false) => {
                let file = self.file;
                self.out
                    .refusals
                    .push(format!("{file}: module `{name}` without exactly one file"));
            }
        }
    }

    /// Judge one `use` tree under the path `prefix`.
    fn use_tree(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(name_of(&path.ident));
                self.use_tree(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(used) => {
                let name = name_of(&used.ident);
                let from_fs = prefix.last().is_some_and(|p| p == "fs");
                if from_fs && FS_FNS.contains(&name.as_str()) {
                    self.refuse(&format!("a `use` of `fs::{name}`"));
                }
                if banned(&name) {
                    self.refuse(&format!("a `use` of the by-path rewriter `{name}`"));
                }
                if name == INCLUDE_MACRO {
                    self.refuse("a `use` of `include`");
                }
            }
            UseTree::Rename(rename) => {
                let from = name_of(&rename.ident);
                let from = if from == "self" {
                    prefix.last().cloned().unwrap_or(from)
                } else {
                    from
                };
                let to = name_of(&rename.rename);
                if rename_refused(&from) || rename_refused(&to) || from == INCLUDE_MACRO {
                    self.refuse(&format!("a renaming `use` of `{from}` as `{to}`"));
                }
            }
            UseTree::Glob(_) => {
                if prefix.last().is_some_and(|p| p == "fs") {
                    self.refuse("a glob `use` of `fs`");
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.use_tree(item, prefix);
                }
            }
        }
    }

    /// Judge a macro body that is not comma-separated expressions, token by token.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let toks = flatten(tokens);
        for tok in &toks {
            match tok {
                Tok::Name(name) if banned(name) => {
                    self.refuse(&format!("the by-path rewriter `{name}`"));
                }
                Tok::Group(_, stream) => self.scan_tokens(stream.clone()),
                _ => {}
            }
        }
        for window in toks.windows(2) {
            match window {
                [Tok::Name(name), Tok::Punct('!')] if name == INCLUDE_MACRO => {
                    self.refuse("an `include!`");
                }
                [Tok::Punct('.'), Tok::Name(method)]
                    if HANDLE_WRITES.contains(&method.as_str()) =>
                {
                    self.hit(format!(".{method}"));
                }
                _ => {}
            }
        }
        for window in toks.windows(3) {
            match window {
                [Tok::Punct(':'), Tok::Punct(':'), Tok::Name(name)]
                    if CREATE_FNS.contains(&name.as_str()) =>
                {
                    self.hit(format!("::{name}"));
                }
                [
                    Tok::Punct('.'),
                    Tok::Name(flag),
                    Tok::Group(Delimiter::Parenthesis, args),
                ] if OPEN_FLAGS.contains(&flag.as_str()) && is_true(args) => {
                    self.hit(format!(".{flag}(true)"));
                }
                _ => {}
            }
        }
        for window in toks.windows(4) {
            if let [
                Tok::Name(module),
                Tok::Punct(':'),
                Tok::Punct(':'),
                Tok::Name(name),
            ] = window
                && module == "fs"
                && FS_FNS.contains(&name.as_str())
            {
                self.hit(format!("fs::{name}"));
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
                self.refuse("an item shape this scan does not read");
            }
            return;
        };
        self.gated(is_test_only(attrs), |s| match item {
            Item::Fn(f) => s.within(name_of(&f.sig.ident), |s| visit::visit_item_fn(s, f)),
            Item::Trait(t) => s.within(name_of(&t.ident), |s| visit::visit_item_trait(s, t)),
            Item::Impl(i) => s.within(impl_name(i), |s| visit::visit_item_impl(s, i)),
            _ => visit::visit_item(s, item),
        });
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        let Some(attrs) = impl_item_attrs(item) else {
            if let ImplItem::Verbatim(tokens) = item {
                self.scan_tokens(tokens.clone());
            } else {
                self.refuse("an impl item shape this scan does not read");
            }
            return;
        };
        self.gated(is_test_only(attrs), |s| {
            if let ImplItem::Fn(f) = item {
                s.within(name_of(&f.sig.ident), |s| visit::visit_impl_item_fn(s, f));
            } else {
                visit::visit_impl_item(s, item);
            }
        });
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        let Some(attrs) = trait_item_attrs(item) else {
            if let TraitItem::Verbatim(tokens) = item {
                self.scan_tokens(tokens.clone());
            } else {
                self.refuse("a trait item shape this scan does not read");
            }
            return;
        };
        self.gated(is_test_only(attrs), |s| {
            if let TraitItem::Fn(f) = item {
                s.within(name_of(&f.sig.ident), |s| visit::visit_trait_item_fn(s, f));
            } else {
                visit::visit_trait_item(s, item);
            }
        });
    }

    fn visit_item_mod(&mut self, item: &'ast ItemMod) {
        if item.attrs.iter().any(names_a_path) {
            let file = self.file;
            self.out
                .refusals
                .push(format!("{file}: a `#[path]` module"));
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

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.use_tree(&item.tree, &mut Vec::new());
    }

    fn visit_ident(&mut self, ident: &'ast Ident) {
        let name = name_of(ident);
        if banned(&name) {
            self.refuse(&format!("the by-path rewriter `{name}`"));
        }
    }

    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| name_of(&segment.ident))
            .collect();
        if let Some(what) = path_write(&segments, path.qself.is_some()) {
            self.hit(what);
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let method = name_of(&call.method);
        if HANDLE_WRITES.contains(&method.as_str()) {
            self.hit(format!(".{method}"));
        } else if OPEN_FLAGS.contains(&method.as_str()) && args_are_true(&call.args) {
            self.hit(format!(".{method}(true)"));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if mac
            .path
            .segments
            .last()
            .is_some_and(|segment| name_of(&segment.ident) == INCLUDE_MACRO)
        {
            let file = self.file;
            self.out.refusals.push(format!("{file}: an `include!`"));
            return;
        }
        visit::visit_macro(self, mac);
        match mac.parse_body_with(Punctuated::<Expr, Token![,]>::parse_terminated) {
            Ok(exprs) => {
                for expr in &exprs {
                    self.visit_expr(expr);
                }
            }
            Err(_) => self.scan_tokens(mac.tokens.clone()),
        }
    }
}

/// Scan one parsed file named `file`.
///
/// It is reached as production or not, and its `mod x;` declarations resolve in `dir`.
fn scan_file(file: &str, dir: PathBuf, production: bool, syntax: &syn::File) -> FileScan {
    let mut scanner = Scanner {
        dir,
        context: Vec::new(),
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

/// Every production write, keyed by file and enclosing fn, with what it calls.
type Hits = BTreeMap<(String, String), BTreeSet<String>>;

/// What the module-tree walk found.
struct Walked {
    /// Every production write.
    hits: Hits,
    /// Every reached file, with whether it was reached as production.
    reached: BTreeMap<String, bool>,
    /// Every refusal, one line each.
    refusals: Vec<String>,
}

/// One queued module file.
///
/// The file, the directory its modules resolve in, its nesting, and whether it
/// is reached as production.
type Queued = (PathBuf, PathBuf, usize, bool);

/// Scan every file reached from `roots`, keyed relative to `root`.
fn walk(root: &Path, roots: Vec<(PathBuf, PathBuf)>) -> Result<Walked, Box<dyn std::error::Error>> {
    let mut scans: BTreeMap<String, FileScan> = BTreeMap::new();
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
    let mut hits = Hits::new();
    for (file, scan) in scans {
        refusals.extend(scan.refusals);
        for (key, what) in scan.hits {
            hits.entry((file.clone(), key)).or_default().insert(what);
        }
    }
    Ok(Walked {
        hits,
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

/// Every write without its row, and every row without its write, one line each.
fn judge(hits: &Hits, sites: &[Site]) -> Vec<String> {
    let mut found = Vec::new();
    let mut listed: BTreeSet<(String, String)> = BTreeSet::new();
    for (file, key, class) in sites {
        let row = ((*file).to_owned(), (*key).to_owned());
        if !listed.insert(row.clone()) {
            found.push(format!("{file}: `{key}` is listed twice in SITES"));
        }
        if !hits.contains_key(&row) {
            found.push(format!(
                "{file}: the {class:?} row for `{key}` names no write; drop the stale row"
            ));
        }
    }
    for ((file, key), whats) in hits {
        if !listed.contains(&(file.clone(), key.clone())) {
            let whats: Vec<&str> = whats.iter().map(String::as_str).collect();
            found.push(format!(
                "{file}: `{key}` writes by path ({}) with no SITES row; rewrite a user \
                 file through `HeldDir`, or list an ipe-owned write with its class",
                whats.join(", ")
            ));
        }
    }
    found
}

/// Every refusal for the tree at `root`, walked from `roots`, against `sites`.
fn verdict(
    root: &Path,
    roots: Vec<(PathBuf, PathBuf)>,
    sites: &[Site],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let Walked {
        hits,
        reached,
        refusals,
    } = walk(root, roots)?;
    let mut paths = Vec::new();
    rust_files(root, 0, &mut paths)?;
    let files = paths
        .iter()
        .map(|path| relative(root, path))
        .collect::<Result<Vec<_>, _>>()?;
    let mut found = refusals;
    found.extend(unreached(&reached, &files));
    found.extend(judge(&hits, sites));
    Ok(found)
}

#[test]
#[allow(clippy::expect_used)] // an unwalkable source tree is the test failure
fn every_production_write_names_its_row() {
    let root = src_root();
    let roots = crate_roots(&root).expect("crate roots listable");
    let walked = walk(&root, roots.clone()).expect("module tree walkable");
    for file in ["output_dir/held.rs", "fmt.rs", "driver/commands_pkg.rs"] {
        assert!(
            walked.reached.get(file) == Some(&true),
            "the walk must reach src/{file} as production, or it is walking the wrong tree"
        );
    }
    let found = verdict(&root, roots, SITES).expect("source tree scannable");
    assert!(
        found.is_empty(),
        "every production filesystem write names its enclosing fn in SITES, and \
         no user file is rewritten by path:\n{}",
        found.join("\n")
    );
}

/// A fresh tree holding `files` (path relative to the tree, contents).
#[allow(clippy::expect_used)] // a failed scratch-tree setup is the test failure
fn tree(label: &str, files: &[(&str, &str)]) -> PathBuf {
    let root = ipe_test_temp::temp_root().join(format!(
        "ipe_user_file_write_scan_{label}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, text) in files {
        let path = root.join(rel);
        let parent = path.parent().expect("a tree file has a parent");
        std::fs::create_dir_all(parent).expect("tree dir is created");
        std::fs::write(&path, text).expect("tree file is written");
    }
    root
}

/// The refusals for a one-crate tree rooted at `lib.rs` holding `files`.
#[allow(clippy::expect_used)] // a fixture that cannot be scanned is the test failure
fn fixture(label: &str, files: &[(&str, &str)], sites: &[Site]) -> Vec<String> {
    let root = tree(label, files);
    let roots = vec![(root.join("lib.rs"), root.clone())];
    let found = verdict(&root, roots, sites).expect("fixture scannable");
    let _ = std::fs::remove_dir_all(&root);
    found
}

/// Whether some line of `found` names `file` and holds `why`.
fn refused_for(found: &[String], file: &str, why: &str) -> bool {
    found
        .iter()
        .any(|line| line.starts_with(&format!("{file}:")) && line.contains(why))
}

/// A raw `fs::write`.
const RAW_WRITE: &str =
    "pub fn save(p: &std::path::Path) -> std::io::Result<()> { std::fs::write(p, b\"x\") }\n";

#[test]
fn a_raw_write_without_its_row_is_refused() {
    let found = fixture("raw", &[("lib.rs", RAW_WRITE)], &[]);
    assert!(
        refused_for(&found, "lib.rs", "`save` writes by path"),
        "{found:?}"
    );
    let listed = fixture(
        "raw_listed",
        &[("lib.rs", RAW_WRITE)],
        &[("lib.rs", "save", SiteClass::Cache)],
    );
    assert!(listed.is_empty(), "{listed:?}");
}

#[test]
fn a_renaming_use_is_refused() {
    for (label, text) in [
        (
            "rename_fn",
            "use std::fs::write as put;\npub fn save() {}\n",
        ),
        ("rename_fs", "use std::fs as disk;\npub fn save() {}\n"),
        (
            "rename_self",
            "use std::fs::{self as disk};\npub fn save() {}\n",
        ),
        ("use_fn", "use std::fs::write;\npub fn save() {}\n"),
        ("use_glob", "use std::fs::*;\npub fn save() {}\n"),
    ] {
        let found = fixture(&format!("use_{label}"), &[("lib.rs", text)], &[]);
        assert!(refused_for(&found, "lib.rs", "`use`"), "{label}: {found:?}");
    }
}

#[test]
fn an_include_is_refused() {
    let found = fixture(
        "include",
        &[
            ("lib.rs", "include!(\"hidden.rs\");\n"),
            ("hidden.rs", RAW_WRITE),
        ],
        &[],
    );
    assert!(refused_for(&found, "lib.rs", "an `include!`"), "{found:?}");
    assert!(
        refused_for(&found, "hidden.rs", "no module declaration reaches"),
        "{found:?}"
    );
}

#[test]
fn a_path_module_is_refused() {
    let found = fixture(
        "path",
        &[
            ("lib.rs", "#[path = \"elsewhere.rs\"]\nmod hidden;\n"),
            ("elsewhere.rs", RAW_WRITE),
        ],
        &[],
    );
    assert!(
        refused_for(&found, "lib.rs", "a `#[path]` module"),
        "{found:?}"
    );
}

#[test]
fn a_stale_row_is_refused() {
    let found = fixture(
        "stale",
        &[("lib.rs", "pub fn save() {}\n")],
        &[("lib.rs", "save", SiteClass::Generated)],
    );
    assert!(refused_for(&found, "lib.rs", "names no write"), "{found:?}");
}

#[test]
fn a_write_under_another_fn_than_its_row_is_refused() {
    let found = fixture(
        "unlisted",
        &[("lib.rs", RAW_WRITE)],
        &[("lib.rs", "load", SiteClass::NewFile)],
    );
    assert!(
        refused_for(&found, "lib.rs", "`save` writes by path"),
        "{found:?}"
    );
    assert!(refused_for(&found, "lib.rs", "names no write"), "{found:?}");
}

#[test]
fn every_write_shape_is_a_hit() {
    for (label, body) in [
        ("create", "let _ = Handle::create(p);"),
        ("create_qself", "let _ = <Handle>::create(p);"),
        ("create_new", "let _ = dir.create_new(p);"),
        ("perm", "let _ = file.set_permissions(m);"),
        (
            "open_write",
            "let _ = std::fs::OpenOptions::new().write(true).open(p);",
        ),
        ("open_append", "let _ = o.append(true);"),
        ("remove", "let _ = std::fs::remove_file(p);"),
        ("rename", "let _ = fs::rename(p, q);"),
        ("link", "let _ = std::os::unix::fs::symlink(p, q);"),
        ("as_value", "let _ = [p].map(fs::remove_file);"),
        ("in_macro", "let _ = vec![fs::write(p, b\"x\")];"),
        ("in_tokens", "m! { fs::write(p, b\"x\") ; }"),
    ] {
        let text = format!("pub fn save() {{ {body} }}\n");
        let found = fixture(&format!("shape_{label}"), &[("lib.rs", text.as_str())], &[]);
        assert!(
            refused_for(&found, "lib.rs", "`save` writes by path"),
            "{label}: {found:?}"
        );
    }
}

#[test]
fn a_by_path_rewriter_name_is_refused() {
    for (label, text) in [
        ("def", "pub fn write_atomic() {}\n"),
        (
            "call",
            "pub fn save() { rewrite_user_file_if_unchanged(); }\n",
        ),
        ("import", "use crate::driver::backup_user_file;\n"),
        ("in_tokens", "pub fn save() { m! { numbered_backup ; } }\n"),
    ] {
        let found = fixture(&format!("banned_{label}"), &[("lib.rs", text)], &[]);
        assert!(
            refused_for(&found, "lib.rs", "by-path rewriter"),
            "{label}: {found:?}"
        );
    }
}

#[test]
fn test_code_and_reads_are_not_hits() {
    let text = r#"
pub fn load(p: &std::path::Path) -> std::io::Result<String> {
    let _ = std::fs::OpenOptions::new().read(true).write(false).open(p);
    std::fs::read_to_string(p)
}
#[cfg(test)]
mod tests {
    #[test]
    fn t() { let _ = std::fs::write("x", b"x"); }
}
#[cfg(all(test, unix))]
fn helper() { let _ = std::fs::remove_file("x"); }
"#;
    let found = fixture("test_code", &[("lib.rs", text)], &[]);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_test_only_file_is_scanned_as_test_code() {
    let found = fixture(
        "test_file",
        &[
            ("lib.rs", "#[cfg(test)]\nmod tests;\n"),
            ("tests.rs", RAW_WRITE),
        ],
        &[],
    );
    assert!(found.is_empty(), "{found:?}");
}

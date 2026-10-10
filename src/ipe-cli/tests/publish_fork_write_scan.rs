#![forbid(unsafe_code)]
//! Pins that publish writes into the index-fork checkout only through held directories.
//!
//! The fork is another party's tree, and git checks a committed symbolic link
//! out as a link, so a path-based write there can land anywhere the fork
//! points it. `publish.rs` reaches the checkout only through
//! `write_fork_entry`, which walks every level through a held directory. This
//! scan parses the non-test items of `src/publish.rs` and refuses any mention
//! of a path-based filesystem API (`fs`, `File`, `OpenOptions`, `DirBuilder`,
//! link creators), macro bodies included, and requires `open_pr` to call
//! `write_fork_entry`.

use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, Meta, Token};

/// Identifiers that name a path-based filesystem API.
const BANNED: &[&str] = &[
    "fs",
    "File",
    "OpenOptions",
    "DirBuilder",
    "hard_link",
    "symlink",
    "symlink_file",
    "symlink_dir",
];

/// The one function that writes into the fork checkout.
const WRITER: &str = "write_fork_entry";

/// The function that opens the index PR and writes the entry.
const CALLER: &str = "open_pr";

/// Whether `meta` holds only under `cfg(test)`.
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

/// Whether `attrs` compile the item only under `cfg(test)`.
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

/// The attributes of `item`; none for an item kind syn adds later.
fn item_attrs(item: &syn::Item) -> &[Attribute] {
    match item {
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        _ => &[],
    }
}

/// What the scan found in the non-test items of one source.
#[derive(Default)]
struct Scan {
    /// The enclosing function names, innermost last.
    fns: Vec<String>,
    /// Each banned identifier met, with the function it sits in.
    reaches: BTreeSet<(String, String)>,
    /// The functions defined.
    defined: BTreeSet<String>,
    /// Whether [`CALLER`] calls [`WRITER`].
    caller_writes_through_writer: bool,
}

impl Scan {
    /// The function the visitor is in, or `<file>` at item level.
    fn site(&self) -> String {
        self.fns
            .last()
            .cloned()
            .unwrap_or_else(|| "<file>".to_owned())
    }

    /// Record every banned identifier of a macro body.
    fn tokens(&mut self, tokens: TokenStream) {
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => self.name(&ident.to_string()),
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }

    /// Record `name` when it is banned.
    fn name(&mut self, name: &str) {
        if BANNED.contains(&name) {
            let site = self.site();
            self.reaches.insert((site, name.to_owned()));
        }
    }

    /// Run `walk` inside the function `name`.
    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.defined.insert(name.clone());
        self.fns.push(name);
        walk(self);
        self.fns.pop();
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !is_test_only(item_attrs(item)) {
            visit::visit_item(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within(item.sig.ident.to_string(), |scan| {
            visit::visit_item_fn(scan, item);
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_only(&item.attrs) {
            return;
        }
        self.within(item.sig.ident.to_string(), |scan| {
            visit::visit_impl_item_fn(scan, item);
        });
    }

    fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
        self.name(&ident.to_string());
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = call.func.as_ref() {
            let calls_writer = path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == WRITER);
            if calls_writer && self.fns.iter().any(|name| name == CALLER) {
                self.caller_writes_through_writer = true;
            }
        }
        visit::visit_expr_call(self, call);
    }
}

/// Scan `source`, the text of a `publish.rs`.
fn scan(source: &str) -> Result<Scan, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse: {e}"))?;
    let mut found = Scan::default();
    found.visit_file(&file);
    Ok(found)
}

/// The refusals `found` earns, one line each.
fn refusals(found: &Scan) -> Vec<String> {
    let mut out: Vec<String> = found
        .reaches
        .iter()
        .map(|(site, name)| format!("`{name}` in `{site}`: a path-based filesystem reach"))
        .collect();
    for required in [WRITER, CALLER] {
        if !found.defined.contains(required) {
            out.push(format!("`{required}` is not defined"));
        }
    }
    if !found.caller_writes_through_writer {
        out.push(format!("`{CALLER}` does not call `{WRITER}`"));
    }
    out
}

/// Production `publish.rs` reaches the fork checkout only through the held writer.
#[test]
fn publish_writes_the_fork_only_through_held_directories() -> Result<(), String> {
    let path = e2e_support::manifest_dir!().join("src").join("publish.rs");
    let source = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let found = scan(&source)?;
    let refused = refusals(&found);
    assert!(
        refused.is_empty(),
        "publish writes into the index-fork checkout only through `{WRITER}`, which holds \
         every level; no path-based filesystem API may appear outside tests:\n{}",
        refused.join("\n")
    );
    Ok(())
}

/// A path-based write in `open_pr`, spelled directly, by alias, or in a macro, is refused.
#[test]
fn a_path_based_fork_write_is_refused() -> Result<(), String> {
    let held = "fn write_fork_entry() {}\nfn open_pr() { write_fork_entry(); }\n";
    assert!(refusals(&scan(held)?).is_empty(), "the held shape passes");
    let breaches = [
        "fn write_fork_entry() {}\nfn open_pr() { std::fs::write(p, b); }\n",
        "use std::fs as disk;\nfn write_fork_entry() {}\nfn open_pr() { write_fork_entry(); }\n",
        "fn write_fork_entry() {}\nfn open_pr() { write_fork_entry(); let _ = vec![std::fs::write(p, b)]; }\n",
        "fn write_fork_entry() {}\nfn open_pr() { write_fork_entry(); File::create(p); }\n",
        "fn write_fork_entry() {}\nfn open_pr() { std::fs::create_dir_all(p); }\n",
        "fn open_pr() {}\n",
    ];
    for source in breaches {
        assert!(!refusals(&scan(source)?).is_empty(), "refused:\n{source}");
    }
    let in_tests = "fn write_fork_entry() {}\nfn open_pr() { write_fork_entry(); }\n\
                    #[cfg(test)]\nmod tests { fn t() { std::fs::write(p, b); } }\n";
    assert!(
        refusals(&scan(in_tests)?).is_empty(),
        "test-only code is out of scope"
    );
    Ok(())
}

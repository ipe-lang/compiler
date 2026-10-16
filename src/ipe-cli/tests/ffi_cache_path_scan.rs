#![forbid(unsafe_code)]
//! Pins that production code builds the FFI cache path from its components, never from its text.
//!
//! `FFI_CACHE_REL` spells the cache path joined by `/`. Below a Windows
//! verbatim root `/` is no separator, so a path joined from that text names one
//! entry, and a walk that splits a cache path on `/` opens a different
//! directory than the one the loader discovers. This scan parses the non-test
//! items of every source that builds or walks the cache and refuses any
//! mention of a `*CACHE_REL` constant, macro bodies and imports included; the
//! one sanctioned use is the build-time assertion that the text and the
//! components agree. It also pins that the owner-checked cache openers take the
//! anchor alone, so no caller can hand them a relative path to split.

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// The sources that build or walk the FFI cache path, relative to the workspace `src/`.
const SOURCES: &[&str] = &[
    "ipe-cli/src/owner_trust.rs",
    "ipe-cli/src/ffi.rs",
    "ipe-cli/src/audit.rs",
    "ipe-cli/src/audit_native.rs",
    "compiler/ffi/src/driver.rs",
];

/// The function whose arguments may name the cache text: the drift assertion.
const SANCTIONED_CALL: &str = "rel_joins";

/// The owner-checked cache openers, each of which must take exactly the anchor.
const ANCHOR_ONLY: &[&str] = &["open_cache", "refuse_unverifiable_cache"];

/// Whether `name` names the cache path as text.
fn is_cache_text(name: &str) -> bool {
    name.ends_with("CACHE_REL")
}

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

/// What the scan found in one source.
#[derive(Default)]
struct Scan {
    /// Inside the arguments of [`SANCTIONED_CALL`].
    sanctioned: bool,
    /// Each refused mention or signature, one line each.
    refused: Vec<String>,
    /// The [`ANCHOR_ONLY`] openers defined, with their parameter counts.
    openers: Vec<(String, usize)>,
}

impl Scan {
    /// Refuse `name` when it names the cache text outside the sanctioned call.
    fn name(&mut self, name: &str, how: &str) {
        if is_cache_text(name) && !self.sanctioned {
            self.refused.push(format!(
                "`{name}` {how}: build the cache path from `FFI_CACHE_COMPONENTS`"
            ));
        }
    }

    /// Refuse every cache-text identifier of a macro body; the arguments of
    /// [`SANCTIONED_CALL`] are the drift assertion's own.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut after_sanctioned = false;
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    self.name(&name, "in a macro body");
                    after_sanctioned = name == SANCTIONED_CALL;
                }
                TokenTree::Group(group) => {
                    if !after_sanctioned {
                        self.tokens(group.stream());
                    }
                    after_sanctioned = false;
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => after_sanctioned = false,
            }
        }
    }

    /// Record an opener's parameter count.
    fn signature(&mut self, sig: &syn::Signature) {
        let name = sig.ident.to_string();
        if ANCHOR_ONLY.contains(&name.as_str()) {
            self.openers.push((name, sig.inputs.len()));
        }
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if is_test_only(item_attrs(item)) {
            return;
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if is_test_only(&item.attrs) {
            return;
        }
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_signature(&mut self, sig: &'ast syn::Signature) {
        self.signature(sig);
        visit::visit_signature(self, sig);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let sanctioned = matches!(
            call.func.as_ref(),
            syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|last| last.ident == SANCTIONED_CALL)
        );
        if sanctioned {
            let outer = self.sanctioned;
            self.sanctioned = true;
            visit::visit_expr_call(self, call);
            self.sanctioned = outer;
        } else {
            visit::visit_expr_call(self, call);
        }
    }

    fn visit_expr_path(&mut self, expr: &'ast syn::ExprPath) {
        if let Some(last) = expr.path.segments.last() {
            self.name(&last.ident.to_string(), "used as a value");
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_use_name(&mut self, name: &'ast syn::UseName) {
        self.name(&name.ident.to_string(), "imported");
        visit::visit_use_name(self, name);
    }

    fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
        self.name(&rename.ident.to_string(), "imported under another name");
        visit::visit_use_rename(self, rename);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Scan `source`.
fn scan(source: &str) -> Result<Scan, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse: {e}"))?;
    let mut found = Scan::default();
    found.visit_file(&file);
    Ok(found)
}

/// The refusals `found` earns; `openers` requires every [`ANCHOR_ONLY`] opener defined.
fn refusals(found: &Scan, openers: bool) -> Vec<String> {
    let mut out = found.refused.clone();
    for (name, inputs) in &found.openers {
        if *inputs != 1 {
            out.push(format!(
                "`{name}` takes {inputs} parameters: it takes the anchor alone and walks `FFI_CACHE_COMPONENTS`"
            ));
        }
    }
    if openers {
        for name in ANCHOR_ONLY {
            if !found.openers.iter().any(|(defined, _)| defined == name) {
                out.push(format!("`{name}` is not defined"));
            }
        }
    }
    out
}

/// The text of `src/<rel>` in the workspace.
fn source_of(rel: &str) -> Result<String, String> {
    let path = e2e_support::manifest_dir!().join("..").join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// No production source builds or splits the FFI cache path from its text.
#[test]
fn the_ffi_cache_path_is_built_from_components() -> Result<(), String> {
    let mut refused = Vec::new();
    for rel in SOURCES {
        let found = scan(&source_of(rel)?)?;
        let openers = rel.ends_with("owner_trust.rs");
        refused.extend(
            refusals(&found, openers)
                .into_iter()
                .map(|line| format!("{rel}: {line}")),
        );
    }
    assert!(
        refused.is_empty(),
        "the FFI cache path is built one component at a time from `FFI_CACHE_COMPONENTS`; \
         refused:\n{}",
        refused.join("\n")
    );
    Ok(())
}

/// A cache path built or split from its text, or an opener handed a relative path, is refused.
#[test]
fn a_planted_text_cache_path_is_refused() -> Result<(), String> {
    let clean = "fn open_cache(anchor: &Path) -> R { for s in FFI_CACHE_COMPONENTS { go(s); } }\n\
        fn refuse_unverifiable_cache(anchor: &Path) -> R { ok() }\n\
        const _: () = assert!(rel_joins(FFI_CACHE_REL, &FFI_CACHE_COMPONENTS));\n\
        #[cfg(test)]\nmod tests { const CACHE_REL: &str = FFI_CACHE_REL; fn t() { root.join(CACHE_REL); } }\n";
    assert!(
        refusals(&scan(clean)?, true).is_empty(),
        "the component walk, the drift assertion and test-only text pass"
    );
    let breaches = [
        "fn walk(root: &Path) { for s in FFI_CACHE_REL.split('/') { go(s); } }\n",
        "fn walk(root: &Path) { root.join(ipe_ffi::driver::FFI_CACHE_REL); }\n",
        "fn walk(root: &Path) { root.ends_with(FFI_CACHE_REL); }\n",
        "const CACHE_REL: &str = ipe_ffi::driver::FFI_CACHE_REL;\nfn walk() {}\n",
        "use ipe_ffi::driver::FFI_CACHE_REL as REL;\nfn walk() { REL.split('/'); }\n",
        "fn walk(root: &Path) { let _ = format!(\"{}\", FFI_CACHE_REL); }\n",
        "fn open_cache(anchor: &Path, rel: &str) -> R { for s in rel.split('/') { go(s); } }\n",
        "fn refuse_unverifiable_cache(anchor: &Path, rel: &str) -> R { ok() }\n",
        "mod held { pub fn open_cache(anchor: &Path, rel: &str) -> R { ok() } }\n",
    ];
    for source in breaches {
        assert!(
            !refusals(&scan(source)?, false).is_empty(),
            "refused:\n{source}"
        );
    }
    assert!(
        !refusals(&scan("fn other() {}\n")?, true).is_empty(),
        "a missing opener is refused"
    );
    Ok(())
}

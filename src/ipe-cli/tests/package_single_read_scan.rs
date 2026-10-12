#![forbid(unsafe_code)]
//! Pins that the package gate judges one captured snapshot, never a re-read of the path.
//!
//! Every verdict the audit, the publish gate and the registry admission reach
//! (capability inference, the audit checks, the admitted digest) is computed
//! over the one `PackageSnapshot` the gate captured. A working-tree reader
//! called beside it would judge bytes the snapshot never saw, so a file swapped
//! mid-gate could change one verdict and not another. This scan parses the
//! non-test items of `src/audit.rs` and `src/publish.rs`, and the admission
//! functions of `src/driver/commands_pkg.rs`, and refuses any mention of a
//! working-tree reader, macro bodies included. Each exempt function is named
//! with the reason it certifies nothing.

use std::collections::BTreeSet;

use proc_macro2::{TokenStream, TokenTree};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{Attribute, Meta, Token};

/// Identifiers that name a working-tree reader of the package.
const BANNED: &[&str] = &[
    "parse_manifest",
    "discover_modules",
    "infer_package_capabilities",
    "read_to_string_capped",
    "read_walked_source",
    "extract_tree",
    "hash_source_tree",
    "include",
];

/// `Type::read` paths that re-read the package from disk.
const BANNED_READS: &[&str] = &["PackageSourceSet", "Lockfile"];

/// Functions that may read the working tree, each with why it certifies nothing.
const EXEMPT: &[(&str, &str)] = &[
    (
        "disclose_package",
        "`ipe doc`'s disclosure: a documentation surface that admits nothing",
    ),
    (
        "regenerate_ffi_bindings",
        "writes the generated FFI bindings the build then reads from the snapshot's set",
    ),
];

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

/// Which functions of a source the scan judges.
#[derive(Clone, Copy)]
enum Scope<'a> {
    /// Every non-test item but the [`EXEMPT`] functions.
    Whole,
    /// Only the named functions.
    Only(&'a [&'a str]),
}

/// What the scan found in one source.
struct Scan<'a> {
    scope: Scope<'a>,
    /// The enclosing function names, innermost last.
    fns: Vec<String>,
    /// Each banned reader met, with the function it sits in.
    reaches: BTreeSet<(String, String)>,
    /// The functions defined.
    defined: BTreeSet<String>,
}

impl Scan<'_> {
    /// The function the visitor is in, or `<file>` at item level.
    fn site(&self) -> String {
        self.fns
            .last()
            .cloned()
            .unwrap_or_else(|| "<file>".to_owned())
    }

    /// Whether the visitor's current position is judged.
    fn judged(&self) -> bool {
        match self.scope {
            Scope::Whole => !self
                .fns
                .iter()
                .any(|name| EXEMPT.iter().any(|(exempt, _)| exempt == name)),
            Scope::Only(names) => self.fns.iter().any(|name| names.contains(&name.as_str())),
        }
    }

    /// Record `name` when it is banned and judged.
    fn name(&mut self, name: &str) {
        if BANNED.contains(&name) && self.judged() {
            let site = self.site();
            self.reaches.insert((site, name.to_owned()));
        }
    }

    /// Record a `Type::read` pair when it re-reads the package and is judged.
    fn pair(&mut self, owner: &str, member: &str) {
        if member == "read" && BANNED_READS.contains(&owner) && self.judged() {
            let site = self.site();
            self.reaches.insert((site, format!("{owner}::read")));
        }
    }

    /// Record every banned reader of a macro body.
    fn tokens(&mut self, tokens: TokenStream) {
        let mut previous: Vec<String> = Vec::new();
        for tree in tokens {
            match tree {
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    self.name(&name);
                    if let [.., owner, colon_a, colon_b] = previous.as_slice()
                        && colon_a == ":"
                        && colon_b == ":"
                    {
                        self.pair(owner, &name);
                    }
                    previous.push(name);
                }
                TokenTree::Group(group) => {
                    self.tokens(group.stream());
                    previous.clear();
                }
                TokenTree::Punct(punct) => previous.push(punct.as_char().to_string()),
                TokenTree::Literal(_) => previous.clear(),
            }
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

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if is_test_only(item_attrs(item)) {
            return;
        }
        if let syn::Item::Mod(module) = item
            && module.content.is_none()
            && matches!(self.scope, Scope::Whole)
        {
            let site = self.site();
            self.reaches.insert((site, format!("mod {}", module.ident)));
        }
        visit::visit_item(self, item);
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

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        for window in names.windows(2) {
            if let [owner, member] = window {
                self.pair(owner, member);
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Scan `source` within `scope`.
fn scan<'a>(source: &str, scope: Scope<'a>) -> Result<Scan<'a>, String> {
    let file = syn::parse_file(source).map_err(|e| format!("parse: {e}"))?;
    let mut found = Scan {
        scope,
        fns: Vec::new(),
        reaches: BTreeSet::new(),
        defined: BTreeSet::new(),
    };
    found.visit_file(&file);
    Ok(found)
}

/// The refusals `found` earns, one line each; `required` names functions that must exist.
fn refusals(found: &Scan<'_>, required: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = found
        .reaches
        .iter()
        .map(|(site, name)| {
            format!("`{name}` in `{site}`: a working-tree read beside the snapshot")
        })
        .collect();
    for name in required {
        if !found.defined.contains(*name) {
            out.push(format!("`{name}` is not defined"));
        }
    }
    out
}

/// The admission functions of `commands_pkg.rs` the scan judges.
const ADMISSION: &[&str] = &[
    "run_audit_entry",
    "certify_versions",
    "audit_version",
    "admit_against_audit",
];

/// The text of `src/<rel>`.
fn source_of(rel: &str) -> Result<String, String> {
    let path = e2e_support::manifest_dir!().join("src").join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// The audit, publish and admission paths read the package only through the captured snapshot.
#[test]
fn the_package_gate_reads_the_package_once() -> Result<(), String> {
    let mut refused = Vec::new();
    for (rel, scope, required) in [
        (
            "audit.rs",
            Scope::Whole,
            &["run_audit_over", "capture_package", "disclose_package"][..],
        ),
        ("publish.rs", Scope::Whole, &["run_publish"][..]),
        ("driver/commands_pkg.rs", Scope::Only(ADMISSION), ADMISSION),
    ] {
        let found = scan(&source_of(rel)?, scope)?;
        refused.extend(
            refusals(&found, required)
                .into_iter()
                .map(|line| format!("{rel}: {line}")),
        );
    }
    let exempt: Vec<String> = EXEMPT
        .iter()
        .map(|(name, why)| format!("`{name}`: {why}"))
        .collect();
    assert!(
        refused.is_empty(),
        "every verdict of the package gate is computed over the one captured snapshot; \
         no working-tree reader may appear outside tests and these exemptions:\n{}\n\
         refused:\n{}",
        exempt.join("\n"),
        refused.join("\n")
    );
    Ok(())
}

/// A working-tree read planted in a judged function, spelled directly, by path or in a macro, is refused.
#[test]
fn a_planted_working_tree_read_is_refused() -> Result<(), String> {
    let clean = "fn run_audit_over() { judge(snapshot); }\n";
    assert!(
        refusals(&scan(clean, Scope::Whole)?, &["run_audit_over"]).is_empty(),
        "the snapshot-only shape passes"
    );
    let breaches = [
        "fn run_audit_over() { crate::project::parse_manifest(p); }\n",
        "fn run_audit_over() { crate::infer_package_capabilities(p); }\n",
        "fn run_audit_over() { crate::resolve::hash_source_tree(root); }\n",
        "fn run_audit_over() { PackageSourceSet::read(p); }\n",
        "fn run_audit_over() { crate::lockfile::Lockfile::read(root); }\n",
        "fn run_audit_over() { let _ = vec![Lockfile::read(root)]; }\n",
        "fn run_audit_over() { let _ = dbg!(discover_modules(src)); }\n",
        "use crate::diff::extract_tree as walk;\nfn run_audit_over() { walk(p); }\n",
        "fn run_audit_over() { include!(\"r.rs\"); }\n",
        "mod reader;\nfn run_audit_over() { reader::r(); }\n",
        "fn other() {}\n",
    ];
    for source in breaches {
        assert!(
            !refusals(&scan(source, Scope::Whole)?, &["run_audit_over"]).is_empty(),
            "refused:\n{source}"
        );
    }
    let exempt = "fn disclose_package() { parse_manifest(p); }\nfn run_audit_over() {}\n";
    assert!(
        refusals(&scan(exempt, Scope::Whole)?, &["run_audit_over"]).is_empty(),
        "a named exemption is out of scope"
    );
    let in_tests =
        "fn run_audit_over() {}\n#[cfg(test)]\nmod tests { fn t() { parse_manifest(p); } }\n";
    assert!(
        refusals(&scan(in_tests, Scope::Whole)?, &["run_audit_over"]).is_empty(),
        "test-only code is out of scope"
    );
    let admission =
        "fn audit_version() { Lockfile::read(root); }\nfn unrelated() { parse_manifest(p); }\n";
    let found = scan(admission, Scope::Only(&["audit_version"]))?;
    assert_eq!(
        refusals(&found, &["audit_version"]).len(),
        1,
        "only the named admission functions are judged"
    );
    Ok(())
}

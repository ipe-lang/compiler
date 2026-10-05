//! Secret-debug scan: no runtime type with a derived `Debug` can print a secret.
//!
//! Every `.rs` file under `src/` is parsed with `syn`. A struct or enum whose
//! derive list names `Debug` is checked under two rules:
//!
//! - a named field whose name carries a secret-role word ([`FIELD_WORDS`]:
//!   `headers`, `cookies`, `token`, `password`, `claims`, …) must have a
//!   redacting type;
//! - a struct whose name carries a secret-role word ([`TYPE_WORDS`]:
//!   `Token`, `Secret`, `Credentials`, `Principal`, `Sid`) must give every field
//!   a redacting type.
//!
//! A redacting type is one whose `Debug` never prints its value: `Redacted<_>`,
//! `Secret`, `Key`, or one of those inside `Option`/`Vec`/`Box`/`Arc`. The only
//! other admitted fields are the named entries of [`ALLOWED`], each of which
//! must still match a field the scan read. A type whose layout the emitter fixes
//! writes its `Debug` through `redacting_debug!` instead of deriving it, which
//! takes it out of this scan's reach and into the macro's exhaustive field list.
//!
//! A value's `IpeStringify` text is the second way it prints, so the same walk
//! pins where that text is written. Outside test code, an `impl IpeStringify`
//! written by hand sits only in [`SHOW_IMPL_FILES`]; every other runtime type
//! renders through a `show_row!` row, which lists its leaf and policy in the
//! show table.
//!
//! The compiler backend's sources (`src`, `rust/src`, `rust/templates`) get a
//! positive check: outside test code, every site that renders through `Debug`
//! sits in a function [`DEBUG_SITES`] lists with its exact count and the reason
//! it is never emitted or is sound to emit. A site is one of:
//!
//! - a string, byte-string or C-string literal, macro tokens included, whose
//!   decoded value holds a [`DEBUG_TEXT`] spelling: a `{…:?}` spec (`{:#?}`,
//!   `{x:?}`), `fmt::Debug`, `Debug::fmt` or `dbg!`. The value is read with its
//!   escapes decoded, so `"{:\x3f}"` counts as `"{:?}"`;
//! - a path with a `fmt::Debug` or `Debug::fmt` step (a `use` included),
//!   counted once per path;
//! - a `dbg!` invocation.
//!
//! A new site, or one more in a listed function, fails the scan; so does a
//! listed entry that matches nothing. The removed `Debug` fallback
//! ([`FALLBACK_TEXT`]) is refused at every site, so an emitted field renders
//! through its show row or as a fixed marker.
//!
//! LIMIT: each literal is matched alone. A spelling assembled from pieces at
//! run time (`"{:?"` then `"}"`, a `char` pushed onto a `String`) is not seen.
//!
//! A node is skipped only when its `cfg` is proven test-only, so an
//! unrecognised shape keeps it scanned.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{Literal, TokenStream, TokenTree};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Fields, GenericArgument, ImplItem, Item, ItemEnum, ItemFn, ItemImpl, ItemMod,
    ItemStruct, Lit, LitByteStr, LitCStr, LitStr, Macro, Path, PathArguments, TraitItem, Type,
    UsePath, UseTree,
};

// The `cfg` classification shared with the dial and print-macro scans.
#[allow(dead_code)] // the shared module's expression classifier serves the other scans
#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// Field-name words that mark a field as holding secret-role data.
const FIELD_WORDS: &[&str] = &[
    "headers",
    "cookie",
    "cookies",
    "token",
    "tokens",
    "secret",
    "secrets",
    "password",
    "passwd",
    "pass",
    "pw",
    "credential",
    "credentials",
    "authorization",
    "auth",
    "claims",
    "bearer",
    "sid",
    "jti",
    "apikey",
];

/// Type-name words that mark every field of a struct as secret-role data.
const TYPE_WORDS: &[&str] = &[
    "token",
    "secret",
    "credential",
    "credentials",
    "principal",
    "sid",
];

/// Type names whose `Debug` never prints the value they hold.
const REDACTING_TYPES: &[&str] = &["Redacted", "Secret", "Key"];

/// Containers a redacting type stays redacting inside.
const TRANSPARENT_CONTAINERS: &[&str] = &["Option", "Vec", "Box", "Arc"];

/// A field the rules flag whose printed value is not a secret.
struct Allowed {
    file: &'static str,
    ty: &'static str,
    field: &'static str,
    /// Why the field's `Debug` output is safe to print.
    #[allow(dead_code)] // documentation carried with the entry
    why: &'static str,
}

/// Every admitted exception, matched exactly by file, type and field.
const ALLOWED: [Allowed; 1] = [Allowed {
    file: "dsn.rs",
    ty: "Credentials",
    field: "user",
    why: "a DSN user name is an identifier; the password beside it is `Secret`",
}];

/// The runtime files allowed a hand-written `impl IpeStringify`: the trait's
/// own module, which holds the container and primitive rows.
const SHOW_IMPL_FILES: &[&str] = &["stringify.rs"];

/// Text that marks a `Debug` rendering: a `{…:?}` format spec, the
/// `fmt::Debug` trait's name, a call of its `Debug::fmt` method, or `dbg!`.
const DEBUG_TEXT: &[&str] = &["?}", "fmt::Debug", "Debug::fmt", "dbg!"];

/// The removed `Debug` fallback's spellings: refused at every site the scan
/// reads, never admitted by a [`DEBUG_SITES`] entry.
const FALLBACK_TEXT: &[&str] = &["stringify::Wrap", ")).dispatch()"];

/// The function name a site outside every function is listed under.
const NO_FUNC: &str = "-";

/// A backend function whose string literals, macro tokens or paths render a
/// value through `Debug`, `count` times.
struct DebugSite {
    file: &'static str,
    func: &'static str,
    count: usize,
    /// Why the `Debug` text never reaches emitted Rust, or why it is sound there.
    #[allow(dead_code)] // documentation carried with the entry
    why: &'static str,
}

const DIAGNOSTIC: &str = "a compiler diagnostic's text, never emitted";
const EXPR_HEAD: &str = "the head of the divergence report's expression dump, never emitted";
const SCHEMA_HASH: &str =
    "a model-schema hash input from a closed fieldless enum's name, never emitted";
const SKELETON_KEY: &str = "a skeleton key from a leaf type's variant name, never emitted";
const ENV_NAME_LITERAL: &str = "quotes a public env name into emitted Rust; a `str`'s `Debug` \
     escapes are Rust string-literal escapes";
const SERDE_REFUSAL: &str = "a serde error carrying a path-refusal diagnostic, never emitted";

/// Every backend function that renders through `Debug`, with its exact count, so
/// a new site anywhere (a new function, or one more in a listed function) fails
/// [`the_backend_renders_through_debug_only_at_listed_sites`].
const DEBUG_SITES: &[DebugSite] = &[
    DebugSite {
        file: "rust/src/emit_doc.rs",
        func: "build_binop_chain",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_doc.rs",
        func: "build_call_binop",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_doc.rs",
        func: "build_db_param_call",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_doc.rs",
        func: "expr_head",
        count: 1,
        why: EXPR_HEAD,
    },
    DebugSite {
        file: "rust/src/emit_expr/expr.rs",
        func: "emit_expr_at",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/ffi.rs",
        func: "callee_name",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/ffi.rs",
        func: "ffi_path",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/func.rs",
        func: "emit_func_value",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/kernel_calls.rs",
        func: "emit_db_call",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/kernel_calls.rs",
        func: "emit_server_call",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/kernel_calls.rs",
        func: "emit_tea_call",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/kernel_calls.rs",
        func: "emit_ui_plan",
        count: 7,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/kernel_calls.rs",
        func: "require_input_sub_shape",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_expr/patterns.rs",
        func: "render_pat",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/emit_model_schema.rs",
        func: "hash_ty",
        count: 2,
        why: SCHEMA_HASH,
    },
    DebugSite {
        file: "rust/src/lib.rs",
        func: "match_template",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/lib.rs",
        func: "resolve_ident",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/lib.rs",
        func: "skeleton_ty",
        count: 1,
        why: SKELETON_KEY,
    },
    DebugSite {
        file: "rust/src/preamble.rs",
        func: "anchor_missing",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "anchor_missing",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "assemble_split_manifest",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "async_runtime_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "check_hydration_state_fields",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "chrono_tz_cargo_toml",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "compression_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "config_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "crypto_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "crypto_core_heavy_cargo_toml",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "csv_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "db_cargo_toml",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "dev_posture_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "drop_prelude_section",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "email_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "emit_program",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "emit_spine",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "ffi_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "http_client_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "insert_app_serde_dependency",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "insert_app_serde_json_dependency",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "jwt_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "locale_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "native_runtime_bindings",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "refuse_lexer_hazards",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "render_env_public_rs",
        count: 1,
        why: ENV_NAME_LITERAL,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "secret_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "server_cargo_toml",
        count: 4,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "ssrf_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "substitute_dep_manifest_anchors",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "tea_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "tui_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "unclassified_wrapper",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "url_cargo_toml",
        count: 1,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "web_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "websocket_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/project.rs",
        func: "webview_cargo_toml",
        count: 3,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "rust/src/static_build.rs",
        func: "staticize_manifest",
        count: 2,
        why: DIAGNOSTIC,
    },
    DebugSite {
        file: "src/lib.rs",
        func: "deserialize",
        count: 1,
        why: SERDE_REFUSAL,
    },
    DebugSite {
        file: "src/lib.rs",
        func: "validate",
        count: 1,
        why: DIAGNOSTIC,
    },
];

/// What the [`DebugScan`] found in the backend sources.
#[derive(Default)]
struct DebugFindings {
    /// `Debug` renderings per `(file, function)`.
    sites: BTreeMap<(String, String), usize>,
    /// Every `file:function: spelling` of the removed fallback.
    fallback: Vec<String>,
}

/// Records every `Debug` rendering of one backend file outside test code.
///
/// Emitted Rust is built only from the backend's string literals, so the scan
/// reads every literal (macro tokens included) and every path; attributes,
/// doc comments and comments never reach emitted text and are skipped.
struct DebugScan<'a> {
    file: &'a str,
    funcs: Vec<String>,
    found: &'a mut DebugFindings,
}

impl DebugScan<'_> {
    fn func(&self) -> String {
        self.funcs.last().map_or(NO_FUNC, String::as_str).to_owned()
    }

    fn debug_site(&mut self) {
        let key = (self.file.to_owned(), self.func());
        let count = self.found.sites.entry(key).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn fallback(&mut self, spelling: &str) {
        let site = format!("{}:{}: {spelling}", self.file, self.func());
        self.found.fallback.push(site);
    }

    /// Check one literal's decoded value.
    fn text(&mut self, text: &str) {
        if DEBUG_TEXT.iter().any(|needle| text.contains(needle)) {
            self.debug_site();
        }
        for spelling in FALLBACK_TEXT {
            if text.contains(spelling) {
                self.fallback(spelling);
            }
        }
    }

    /// Check a byte-string literal; one char per byte keeps every ASCII needle
    /// matchable whatever the bytes are, with nothing replaced.
    fn bytes(&mut self, bytes: &[u8]) {
        let text: String = bytes.iter().copied().map(char::from).collect();
        self.text(&text);
    }

    /// Check one unparsed literal token by its decoded value.
    fn literal(&mut self, token: Literal) {
        let source = token.to_string();
        match Lit::new(token) {
            Lit::Str(lit) => self.text(&lit.value()),
            Lit::ByteStr(lit) => self.bytes(&lit.value()),
            Lit::CStr(lit) => self.text(&lit.value().to_string_lossy()),
            // `Lit` is `#[non_exhaustive]`; a number, `char`, byte or bool
            // literal holds no format text, and its source is still read.
            _ => self.text(&source),
        }
    }

    /// Check one path's `first::second` steps: a `Debug` step counts the path
    /// once, a fallback step is refused at each spelling.
    fn path(&mut self, names: &[String]) {
        let mut debug = false;
        for step in names.windows(2) {
            if let [first, second] = step {
                match (first.as_str(), second.as_str()) {
                    ("fmt", "Debug") | ("Debug", "fmt") => debug = true,
                    ("stringify", "Wrap") => self.fallback("stringify::Wrap"),
                    _ => {}
                }
            }
        }
        if debug {
            self.debug_site();
        }
    }

    /// Check a macro's unparsed tokens: their literals, `a::b::…` paths and
    /// nested `dbg!` invocations.
    fn tokens(&mut self, stream: TokenStream) {
        let trees: Vec<TokenTree> = stream.into_iter().collect();
        let mut rest = trees.as_slice();
        while let Some((head, tail)) = rest.split_first() {
            rest = tail;
            match head {
                TokenTree::Group(group) => self.tokens(group.stream()),
                TokenTree::Literal(lit) => self.literal(lit.clone()),
                TokenTree::Ident(first) => {
                    let mut names = vec![first.to_string()];
                    while let [
                        TokenTree::Punct(a),
                        TokenTree::Punct(b),
                        TokenTree::Ident(next),
                        more @ ..,
                    ] = rest
                        && a.as_char() == ':'
                        && b.as_char() == ':'
                    {
                        names.push(next.to_string());
                        rest = more;
                    }
                    let bang =
                        matches!(rest.first(), Some(TokenTree::Punct(p)) if p.as_char() == '!');
                    if names.len() > 1 {
                        self.path(&names);
                    } else if bang && first == "dbg" {
                        self.debug_site();
                    }
                }
                TokenTree::Punct(_) => {}
            }
        }
    }

    /// Walk a function's item with its name as the current site.
    fn within(&mut self, name: String, walk: impl FnOnce(&mut Self)) {
        self.funcs.push(name);
        walk(self);
        self.funcs.pop();
    }
}

/// The last names a `use` tree imports directly below its `fmt::` or
/// `stringify::` prefix.
fn use_leaves(tree: &UseTree) -> Vec<String> {
    match tree {
        UseTree::Name(name) => vec![name.ident.to_string()],
        UseTree::Rename(rename) => vec![rename.ident.to_string()],
        UseTree::Group(group) => group.items.iter().flat_map(use_leaves).collect(),
        UseTree::Path(_) | UseTree::Glob(_) => Vec::new(),
    }
}

impl<'ast> Visit<'ast> for DebugScan<'_> {
    fn visit_attribute(&mut self, _: &'ast Attribute) {}

    fn visit_item(&mut self, node: &'ast Item) {
        if cfg_test_only(item_attrs(node)) {
            return;
        }
        if let Item::Fn(f) = node {
            if !is_test_fn(&f.attrs) {
                self.within(f.sig.ident.to_string(), |scan| {
                    visit::visit_item(scan, node)
                });
            }
            return;
        }
        visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast ImplItem) {
        if cfg_test_only(impl_item_attrs(node)) {
            return;
        }
        if let ImplItem::Fn(f) = node {
            if !is_test_fn(&f.attrs) {
                self.within(f.sig.ident.to_string(), |scan| {
                    visit::visit_impl_item(scan, node);
                });
            }
            return;
        }
        visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast TraitItem) {
        if cfg_test_only(trait_item_attrs(node)) {
            return;
        }
        if let TraitItem::Fn(f) = node {
            if !is_test_fn(&f.attrs) {
                self.within(f.sig.ident.to_string(), |scan| {
                    visit::visit_trait_item(scan, node);
                });
            }
            return;
        }
        visit::visit_trait_item(self, node);
    }

    fn visit_lit_str(&mut self, node: &'ast LitStr) {
        self.text(&node.value());
    }

    fn visit_lit_byte_str(&mut self, node: &'ast LitByteStr) {
        self.bytes(&node.value());
    }

    fn visit_lit_cstr(&mut self, node: &'ast LitCStr) {
        self.text(&node.value().to_string_lossy());
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        visit::visit_macro(self, node);
        if node.path.segments.last().is_some_and(|s| s.ident == "dbg") {
            self.debug_site();
        }
        self.tokens(node.tokens.clone());
    }

    fn visit_path(&mut self, node: &'ast Path) {
        let names: Vec<String> = node.segments.iter().map(|s| s.ident.to_string()).collect();
        self.path(&names);
        visit::visit_path(self, node);
    }

    fn visit_use_path(&mut self, node: &'ast UsePath) {
        let first = node.ident.to_string();
        for second in use_leaves(&node.tree) {
            self.path(&[first.clone(), second]);
        }
        visit::visit_use_path(self, node);
    }
}

/// Every `Debug` rendering and fallback spelling of `sources`.
#[allow(clippy::expect_used)] // an unparsable source must fail the scan, never be skipped
fn debug_findings(sources: &[(String, String)]) -> DebugFindings {
    let mut found = DebugFindings::default();
    for (name, src) in sources {
        let tree = syn::parse_file(src).expect("a backend source parses");
        let mut scan = DebugScan {
            file: name,
            funcs: Vec::new(),
            found: &mut found,
        };
        scan.visit_file(&tree);
    }
    found
}

/// Every disagreement between the found `sites` and the `listed` ones: a site
/// no entry lists, a count that differs, or an entry the scan never matched.
fn unlisted_debug_sites(
    sites: &BTreeMap<(String, String), usize>,
    listed: &[DebugSite],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ((file, func), count) in sites {
        let entry = listed
            .iter()
            .find(|e| e.file == file.as_str() && e.func == func.as_str());
        match entry {
            Some(e) if e.count == *count => {}
            Some(e) => out.push(format!(
                "{file}:{func}: {count} `Debug` sites, listed {}",
                e.count
            )),
            None => out.push(format!("{file}:{func}: {count} unlisted `Debug` sites")),
        }
    }
    for e in listed {
        let key = (e.file.to_owned(), e.func.to_owned());
        if !sites.contains_key(&key) {
            out.push(format!(
                "{}:{}: stale entry, no `Debug` site",
                e.file, e.func
            ));
        }
    }
    out
}

/// The backend sources the emit scan reads, as `dir/relative-path`.
fn backend_sources() -> Vec<(String, String)> {
    let backend = e2e_support::manifest_dir!().join("../../compiler/backend");
    let mut sources: Vec<(String, String)> = Vec::new();
    for dir in ["src", "rust/src", "rust/templates"] {
        let root = backend.join(dir);
        assert!(root.is_dir(), "the backend tree has no {}", root.display());
        sources.extend(
            rust_sources(&root)
                .into_iter()
                .map(|(name, src)| (format!("{dir}/{name}"), src)),
        );
    }
    sources
}

/// The words of an identifier, split at `_` and at lower-to-upper case changes.
fn words(ident: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in ident.chars() {
        if c == '_' {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
        cur.push(c.to_ascii_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Whether `ident` carries one of `set`'s words.
fn has_word(ident: &str, set: &[&str]) -> bool {
    words(ident).iter().any(|w| set.contains(&w.as_str()))
}

/// Whether one of `attrs` is a `#[derive(…)]` naming `Debug`.
fn derives_debug(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("derive")
            && attr
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|paths| {
                    paths
                        .iter()
                        .any(|p| p.segments.last().is_some_and(|s| s.ident == "Debug"))
                })
    })
}

/// Whether `ty`'s `Debug` never prints the value it holds.
fn redacting(ty: &Type) -> bool {
    match ty {
        Type::Path(tp) => tp.path.segments.last().is_some_and(|seg| {
            let name = seg.ident.to_string();
            if REDACTING_TYPES.contains(&name.as_str()) {
                return true;
            }
            if !TRANSPARENT_CONTAINERS.contains(&name.as_str()) {
                return false;
            }
            match &seg.arguments {
                PathArguments::AngleBracketed(args) => {
                    let mut types = args.args.iter().filter_map(|a| match a {
                        GenericArgument::Type(t) => Some(t),
                        _ => None,
                    });
                    types.next().is_some_and(redacting) && types.next().is_none()
                }
                _ => false,
            }
        }),
        Type::Reference(r) => redacting(&r.elem),
        Type::Paren(p) => redacting(&p.elem),
        Type::Group(g) => redacting(&g.elem),
        _ => false,
    }
}

/// One flagged field: `(file, type, field)`.
type Hit = (String, String, String);

/// Collects every flagged field of one file.
struct Scan<'a> {
    file: &'a str,
    hits: Vec<Hit>,
}

impl Scan<'_> {
    /// Check `fields` of the `ty` type; `whole` flags every field, not only
    /// secret-role names.
    fn check(&mut self, ty: &str, fields: &Fields, whole: bool) {
        for (i, field) in fields.iter().enumerate() {
            if cfg_test_only(&field.attrs) {
                continue;
            }
            let name = field
                .ident
                .as_ref()
                .map_or_else(|| i.to_string(), ToString::to_string);
            let named_secret = field
                .ident
                .as_ref()
                .is_some_and(|id| has_word(&id.to_string(), FIELD_WORDS));
            if (whole || named_secret) && !redacting(&field.ty) {
                self.hits.push((self.file.to_owned(), ty.to_owned(), name));
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scan<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if !cfg_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // A `#[test]` / `#[tokio::test]` function exists only under `test`.
        if !is_test_fn(&node.attrs) && !cfg_test_only(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if !cfg_test_only(&node.attrs) {
            visit::visit_item_impl(self, node);
        }
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if cfg_test_only(&node.attrs) {
            return;
        }
        if derives_debug(&node.attrs) {
            let name = node.ident.to_string();
            self.check(&name, &node.fields, has_word(&name, TYPE_WORDS));
        }
        visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast ItemEnum) {
        if cfg_test_only(&node.attrs) {
            return;
        }
        if derives_debug(&node.attrs) {
            let name = node.ident.to_string();
            for variant in &node.variants {
                if !cfg_test_only(&variant.attrs) {
                    self.check(&name, &variant.fields, false);
                }
            }
        }
        visit::visit_item_enum(self, node);
    }
}

/// Every flagged field of `src`, read as the file `file`.
#[allow(clippy::expect_used)] // an unparsable source must fail the scan, never be skipped
fn hits(file: &str, src: &str) -> Vec<Hit> {
    let tree = syn::parse_file(src).expect("a runtime source parses");
    let mut scan = Scan {
        file,
        hits: Vec::new(),
    };
    scan.visit_file(&tree);
    scan.hits
}

/// Whether `hit` is an [`ALLOWED`] entry.
fn allowed(hit: &Hit) -> bool {
    ALLOWED
        .iter()
        .any(|a| a.file == hit.0 && a.ty == hit.1 && a.field == hit.2)
}

/// No runtime source has a derived `Debug` that prints a secret-role field, and
/// every allowlist entry matches a field the scan flagged.
#[test]
fn no_derived_debug_prints_a_secret() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in [
        "server.rs",
        "principal.rs",
        "dsn.rs",
        "secret.rs",
        "redact.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let all: Vec<Hit> = sources
        .iter()
        .flat_map(|(name, src)| hits(name, src))
        .collect();
    let violations: Vec<&Hit> = all.iter().filter(|h| !allowed(h)).collect();
    assert_eq!(violations, Vec::<&Hit>::new());
    for entry in &ALLOWED {
        assert!(
            all.iter()
                .any(|h| h.0 == entry.file && h.1 == entry.ty && h.2 == entry.field),
            "stale allowlist entry {}::{}.{}",
            entry.file,
            entry.ty,
            entry.field
        );
    }
}

/// Whether `attrs` mark a `#[test]` / `#[tokio::test]` function.
fn is_test_fn(attrs: &[Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test"))
}

/// Collects every non-test hand-written `impl IpeStringify` of one file, as
/// `file:Type`.
struct ShowImplScan<'a> {
    file: &'a str,
    hits: Vec<String>,
}

impl<'ast> Visit<'ast> for ShowImplScan<'_> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if !cfg_test_only(&node.attrs) {
            visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if !is_test_fn(&node.attrs) && !cfg_test_only(&node.attrs) {
            visit::visit_item_fn(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if cfg_test_only(&node.attrs) {
            return;
        }
        let shows = node.trait_.as_ref().is_some_and(|(path, _)| {
            path.segments
                .last()
                .is_some_and(|seg| seg.ident == "IpeStringify")
        });
        if shows {
            let ty = match &*node.self_ty {
                Type::Path(tp) => tp
                    .path
                    .segments
                    .last()
                    .map_or_else(String::new, |seg| seg.ident.to_string()),
                _ => "<type>".to_owned(),
            };
            self.hits.push(format!("{}:{ty}", self.file));
        }
        visit::visit_item_impl(self, node);
    }
}

/// Every non-test hand-written `impl IpeStringify` of `src`, read as `file`.
#[allow(clippy::expect_used)] // an unparsable source must fail the scan, never be skipped
fn show_impls(file: &str, src: &str) -> Vec<String> {
    let tree = syn::parse_file(src).expect("a runtime source parses");
    let mut scan = ShowImplScan {
        file,
        hits: Vec::new(),
    };
    scan.visit_file(&tree);
    scan.hits
}

/// The hand-written `impl IpeStringify` sites of `sources` outside
/// [`SHOW_IMPL_FILES`].
fn stray_show_impls(sources: &[(String, String)]) -> Vec<String> {
    sources
        .iter()
        .filter(|(name, _)| !SHOW_IMPL_FILES.contains(&name.as_str()))
        .flat_map(|(name, src)| show_impls(name, src))
        .collect()
}

/// Outside test code, a runtime type's `IpeStringify` is a `show_row!` row
/// unless it sits in [`SHOW_IMPL_FILES`], and each listed file still holds one.
#[test]
fn every_runtime_show_impl_is_a_listed_row() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    assert_eq!(stray_show_impls(&sources), Vec::<String>::new());
    for file in SHOW_IMPL_FILES {
        let held = sources
            .iter()
            .find(|(name, _)| name == file)
            .map(|(name, src)| show_impls(name, src));
        assert!(
            held.is_some_and(|impls| !impls.is_empty()),
            "stale show-impl file {file}"
        );
    }
}

/// Outside test code, the backend renders through `Debug` only at the
/// [`DEBUG_SITES`] entries, each matched with its exact count, and never spells
/// the removed fallback.
#[test]
fn the_backend_renders_through_debug_only_at_listed_sites() {
    let sources = backend_sources();
    assert!(
        sources
            .iter()
            .any(|(name, _)| name == "rust/src/emit_types.rs"),
        "the backend walk did not read rust/src/emit_types.rs"
    );
    let mut keys: Vec<(&str, &str)> = DEBUG_SITES.iter().map(|e| (e.file, e.func)).collect();
    keys.sort_unstable();
    let listed = keys.len();
    keys.dedup();
    assert_eq!(keys.len(), listed, "a `DEBUG_SITES` entry is listed twice");
    let found = debug_findings(&sources);
    assert_eq!(found.fallback, Vec::<String>::new());
    assert_eq!(
        unlisted_debug_sites(&found.sites, DEBUG_SITES),
        Vec::<String>::new()
    );
}

/// The scan counts a new `Debug` site and refuses the fallback spellings,
/// while test code, attributes and doc comments stay out of its count.
#[test]
fn a_new_backend_debug_site_is_refused() {
    let src = r#"
        //! `{x:?}` in a module doc is never emitted.
        /// `fmt::Debug` in a doc comment is never emitted.
        fn listed(v: &str) -> String { format!("{v:?}") }
        fn offending(v: &str) -> String { let mut s = String::new(); s.push_str(&format!("({v:#?})")); s }
        fn bound<T: std::fmt::Debug>(_: T) {}
        fn fallback(b: &str) -> String { format!("(&ipe_runtime::stringify::Wrap({b})).dispatch()") }
        impl Emit { fn method(&self) -> String { concat!("x", "{:?}").to_owned() } }
        #[allow(clippy::useless_format, reason = "{x:?}")]
        fn attributed() -> String { String::new() }
        #[cfg(test)] mod tests { fn probe(v: &str) -> String { format!("{v:?}") } }
        #[test] fn case() { let _ = format!("{:?}", 1); }
        #[cfg(all(test, feature = "web"))] fn gated(v: &str) -> String { format!("{v:?}") }
        const TOP: &str = "{:?}";
    "#;
    let sources = [("emit.rs".to_owned(), src.to_owned())];
    let found = debug_findings(&sources);
    let sites: Vec<(&str, &str, usize)> = found
        .sites
        .iter()
        .map(|((file, func), count)| (file.as_str(), func.as_str(), *count))
        .collect();
    assert_eq!(
        sites,
        [
            ("emit.rs", "-", 1),
            ("emit.rs", "bound", 1),
            ("emit.rs", "listed", 1),
            ("emit.rs", "method", 1),
            ("emit.rs", "offending", 1),
        ]
    );
    assert_eq!(
        found.fallback,
        [
            "emit.rs:fallback: stringify::Wrap",
            "emit.rs:fallback: )).dispatch()"
        ]
    );
    let listed = [
        DebugSite {
            file: "emit.rs",
            func: "listed",
            count: 1,
            why: DIAGNOSTIC,
        },
        DebugSite {
            file: "emit.rs",
            func: "offending",
            count: 2,
            why: DIAGNOSTIC,
        },
        DebugSite {
            file: "emit.rs",
            func: "gone",
            count: 1,
            why: DIAGNOSTIC,
        },
    ];
    assert_eq!(
        unlisted_debug_sites(&found.sites, &listed),
        [
            "emit.rs:-: 1 unlisted `Debug` sites",
            "emit.rs:bound: 1 unlisted `Debug` sites",
            "emit.rs:method: 1 unlisted `Debug` sites",
            "emit.rs:offending: 1 `Debug` sites, listed 2",
            "emit.rs:gone: stale entry, no `Debug` site",
        ]
    );
}

/// One more `Debug` rendering in a listed function breaks its exact count.
#[test]
fn one_more_debug_site_in_a_listed_function_is_refused() {
    let one = [(
        "emit.rs".to_owned(),
        "fn report(k: &str) -> String { format!(\"kernel {k:?}\") }".to_owned(),
    )];
    let two = [(
        "emit.rs".to_owned(),
        "fn report(k: &str) -> String { format!(\"kernel {k:?}\") + &format!(\"{k:?}\") }"
            .to_owned(),
    )];
    let listed = [DebugSite {
        file: "emit.rs",
        func: "report",
        count: 1,
        why: DIAGNOSTIC,
    }];
    assert_eq!(
        unlisted_debug_sites(&debug_findings(&one).sites, &listed),
        Vec::<String>::new()
    );
    assert_eq!(
        unlisted_debug_sites(&debug_findings(&two).sites, &listed),
        ["emit.rs:report: 2 `Debug` sites, listed 1"]
    );
}

/// A literal is read by its decoded value, so an escaped `{:?}` still counts,
/// and every other way to render through `Debug` counts too: a `Debug::fmt`
/// path or spelling, and `dbg!` as an invocation or a spelling.
#[test]
fn an_escaped_or_other_debug_entry_is_refused() {
    let src = r#"
        fn hex_escape(v: u8) -> String { format!("{:\x3f}", v) }
        fn unicode_escape() -> String { String::from("{:\u{3f}}") }
        fn alternate_escape() -> String { String::from("{v:#\x3f}") }
        fn byte_escape() -> &'static [u8] { b"{:\x3f}" }
        fn cstr_escape() -> &'static CStr { c"{:\x3f}" }
        fn trait_name_escape() -> String { String::from("fmt::Debu\x67") }
        fn method_text() -> String { String::from("Debug::fmt(&v, f)") }
        fn method_path(v: &u8, f: &mut Formatter) -> Result { Debug::fmt(v, f) }
        fn full_path(v: &u8, f: &mut Formatter) -> Result { std::fmt::Debug::fmt(v, f) }
        fn method_in_macro(v: &u8, f: &mut Formatter) -> Vec<Result> { vec![Debug::fmt(v, f)] }
        fn dbg_text() -> String { String::from("dbg!(v)") }
        fn dbg_call(v: u8) -> u8 { dbg!(v) }
        fn dbg_qualified(v: u8) -> u8 { std::dbg!(v) }
        fn dbg_in_macro() -> Vec<u8> { vec![dbg!(1)] }
        fn plain(v: &str) -> String { format!("{v}") }
    "#;
    let sources = [("emit.rs".to_owned(), src.to_owned())];
    let found = debug_findings(&sources);
    let sites: Vec<(&str, usize)> = found
        .sites
        .iter()
        .map(|((_, func), count)| (func.as_str(), *count))
        .collect();
    assert_eq!(
        sites,
        [
            ("alternate_escape", 1),
            ("byte_escape", 1),
            ("cstr_escape", 1),
            ("dbg_call", 1),
            ("dbg_in_macro", 1),
            ("dbg_qualified", 1),
            ("dbg_text", 1),
            ("full_path", 1),
            ("hex_escape", 1),
            ("method_in_macro", 1),
            ("method_path", 1),
            ("method_text", 1),
            ("trait_name_escape", 1),
            ("unicode_escape", 1),
        ]
    );
    assert_eq!(found.fallback, Vec::<String>::new());
}

#[test]
fn a_hand_written_show_impl_outside_the_listed_files_is_refused() {
    let src = "impl IpeStringify for Widget { fn ipe_show(&self) -> String { String::new() } }
        impl<T> crate::stringify::IpeStringify for Holder<T> { fn ipe_show(&self) -> String { String::new() } }
        impl std::fmt::Display for Widget { fn fmt(&self, f: &mut Formatter) -> Result { Ok(()) } }
        show_row!(\"Widget\", Value, [] Widget, |w| w.0.ipe_show());
        #[cfg(test)] mod tests { impl IpeStringify for Probe { fn ipe_show(&self) -> String { String::new() } } }
        #[cfg(all(test, feature = \"tui\"))] impl IpeStringify for Gated { fn ipe_show(&self) -> String { String::new() } }";
    let sources = [
        ("widget.rs".to_owned(), src.to_owned()),
        ("stringify.rs".to_owned(), src.to_owned()),
    ];
    assert_eq!(
        stray_show_impls(&sources),
        ["widget.rs:Widget", "widget.rs:Holder"]
    );
}

/// The flagged fields of a fixture, as `type.field` strings.
fn fixture_hits(src: &str) -> Vec<String> {
    hits("fixture.rs", src)
        .into_iter()
        .map(|(_, ty, field)| format!("{ty}.{field}"))
        .collect()
}

#[test]
fn a_plain_secret_role_field_is_refused() {
    let src = "#[derive(Clone, Debug)]
        pub struct Req { pub path: String, pub headers: HashMap<String, String>, authToken: String }
        #[derive(std::fmt::Debug)]
        enum Ev { Login { password: String }, Tick(i64) }";
    assert_eq!(
        fixture_hits(src),
        ["Req.headers", "Req.authToken", "Ev.password"]
    );
}

#[test]
fn every_field_of_a_secret_role_struct_is_refused() {
    let src = "#[derive(Debug)] struct ApiToken(String);
        #[derive(Debug)] struct SessionSid { raw: String, issued: i64 }";
    assert_eq!(
        fixture_hits(src),
        ["ApiToken.0", "SessionSid.raw", "SessionSid.issued"]
    );
}

#[test]
fn redacting_fields_and_test_only_items_are_admitted() {
    let src = "#[derive(Debug)]
        struct Req { headers: Redacted<HashMap<String, String>>, cookie: crate::redact::Redacted<String>,
                     password: Option<Secret>, tokens: Vec<Secret>, key: Key }
        #[derive(Debug)] struct ApiToken(Redacted<String>);
        struct NoDebug { password: String }
        #[cfg(test)] #[derive(Debug)] struct Fixture { password: String }
        #[cfg(test)] mod tests { #[derive(Debug)] struct Inner { token: String } }
        #[tokio::test] async fn t() { #[derive(Debug)] struct Local { token: String } }
        #[derive(Debug)] struct Passive { passive: String, header: Vec<String> }";
    assert_eq!(fixture_hits(src), Vec::<String>::new());
}

#[test]
fn an_unproven_cfg_keeps_the_item_scanned() {
    let src = "#[cfg(not(test))] #[derive(Debug)] struct A { token: String }
        #[cfg(any(test, feature = \"server\"))] #[derive(Debug)] struct B { cookies: Vec<String> }
        #[derive(Debug)] struct C { token: Option<String> }";
    assert_eq!(fixture_hits(src), ["A.token", "B.cookies", "C.token"]);
}

#[test]
fn a_flagged_field_outside_the_allowlist_is_not_allowed() {
    let user = (
        "dsn.rs".to_owned(),
        "Credentials".to_owned(),
        "user".to_owned(),
    );
    assert!(allowed(&user));
    let elsewhere = (
        "db.rs".to_owned(),
        "Credentials".to_owned(),
        "user".to_owned(),
    );
    assert!(!allowed(&elsewhere));
    let other_field = (
        "dsn.rs".to_owned(),
        "Credentials".to_owned(),
        "host".to_owned(),
    );
    assert!(!allowed(&other_field));
}

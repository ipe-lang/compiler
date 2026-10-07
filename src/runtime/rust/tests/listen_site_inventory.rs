//! Listen-site inventory: every socket the runtime binds outside test code is
//! one of the admitted sites.
//!
//! An app listener binds only through `server::bind_app_listener`, whose
//! address is a typed `ListenHost` that cannot name a non-loopback address
//! without the opt-in that chose it. A second `TcpListener::bind` would be a
//! listener the resolver and its startup warning never see, so the scan counts,
//! per file and enclosing function, every production-syntax bind form and
//! asserts the counts equal [`ADMITTED`]. A new site, a dropped one, or one
//! moved into another function turns the scan red.
//!
//! Every `.rs` file under `src/` is parsed with `syn`, so comments and string
//! literals are never code, and a `#[cfg(...)]` proven test-only removes
//! exactly the node it is attached to. A node whose `cfg` is not proven
//! test-only is scanned, and a file that does not parse fails the scan. A
//! macro body is scanned token by token with no `#[cfg(test)]` honoured.
//!
//! Counted forms:
//! - a path ending in `<type>::bind` for every type in [`BIND_TYPES`], called
//!   or not (a call, a fn pointer), whatever its qualifying prefix;
//! - every path segment naming [`SOCKET_BUILDER`], whose bind is a method;
//! - a `use` renaming one of those types, recorded under its own key, so an
//!   alias never hides the binds made through it.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, Field, FieldValue, ForeignItem, ImplItem, Item, Macro, Path, Stmt,
    TraitItem, UseTree, Variant,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

/// The socket types whose associated `bind` opens a listening socket.
const BIND_TYPES: &[&str] = &["TcpListener", "UdpSocket"];

/// The socket type whose `bind` is a method on a built socket, counted at
/// every path naming it.
const SOCKET_BUILDER: &str = "TcpSocket";

/// The enclosing name of a site outside every function.
const MODULE_LEVEL: &str = "<module>";

/// Every admitted bind site: file, enclosing function, counted form, count.
const ADMITTED: &[(&str, &str, &str, usize)] = &[
    // The one app listener; its address is a resolved `ListenHost`.
    ("server.rs", "bind_app_listener", "TcpListener::bind", 1),
    // The control channel: a loopback address, re-checked `is_loopback`
    // before the bind.
    ("control.rs", "serve_control", "TcpListener::bind", 1),
    // A free-port probe on the `127.0.0.1:0` literal, dropped unaccepted.
    (
        "web/console_proxy.rs",
        "pick_free_port",
        "TcpListener::bind",
        1,
    ),
];

/// Every bind form in the production syntax of one file, by enclosing
/// function and counted form.
#[derive(Default)]
struct Scan {
    fns: Vec<String>,
    sites: BTreeMap<(String, String), usize>,
}

impl Scan {
    fn record(&mut self, form: String) {
        let within = self
            .fns
            .last()
            .cloned()
            .unwrap_or_else(|| MODULE_LEVEL.to_owned());
        let count = self.sites.entry((within, form)).or_insert(0);
        *count = count.saturating_add(1);
    }

    /// Records the bind forms in a path given as its segment names.
    fn segments(&mut self, names: &[String]) {
        for (at, name) in names.iter().enumerate() {
            if BIND_TYPES.contains(&name.as_str())
                && names.get(at.saturating_add(1)).is_some_and(|n| n == "bind")
            {
                self.record(format!("{name}::bind"));
            }
            if name == SOCKET_BUILDER {
                self.record(SOCKET_BUILDER.to_owned());
            }
        }
    }

    /// Records every bind form in `tokens`, at any group depth.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let mut path: Vec<String> = Vec::new();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => {
                    self.segments(&std::mem::take(&mut path));
                    self.scan_tokens(group.stream());
                }
                TokenTree::Ident(id) => {
                    let joined = at.checked_sub(2).is_some_and(|before| {
                        matches!(
                            (trees.get(before), trees.get(before.saturating_add(1))),
                            (Some(TokenTree::Punct(a)), Some(TokenTree::Punct(b)))
                                if a.as_char() == ':' && b.as_char() == ':'
                        )
                    });
                    if !joined {
                        self.segments(&std::mem::take(&mut path));
                    }
                    path.push(id.unraw().to_string());
                }
                TokenTree::Punct(p) if p.as_char() == ':' => {}
                TokenTree::Punct(_) | TokenTree::Literal(_) => {
                    self.segments(&std::mem::take(&mut path));
                }
            }
        }
        self.segments(&path);
    }

    /// Scans a function body under its name.
    fn within<F: FnOnce(&mut Self)>(&mut self, name: String, scan: F) {
        self.fns.push(name);
        scan(self);
        self.fns.pop();
    }
}

impl<'ast> Visit<'ast> for Scan {
    fn visit_item(&mut self, item: &'ast Item) {
        if cfg_test_only(item_attrs(item)) {
            return;
        }
        match item {
            Item::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            Item::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.within(name, |scan| visit::visit_item(scan, item));
                return;
            }
            _ => {}
        }
        visit::visit_item(self, item);
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if cfg_test_only(impl_item_attrs(item)) {
            return;
        }
        match item {
            ImplItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            ImplItem::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.within(name, |scan| visit::visit_impl_item(scan, item));
                return;
            }
            _ => {}
        }
        visit::visit_impl_item(self, item);
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if cfg_test_only(trait_item_attrs(item)) {
            return;
        }
        match item {
            TraitItem::Verbatim(tokens) => self.scan_tokens(tokens.clone()),
            TraitItem::Fn(f) => {
                let name = f.sig.ident.unraw().to_string();
                self.within(name, |scan| visit::visit_trait_item(scan, item));
                return;
            }
            _ => {}
        }
        visit::visit_trait_item(self, item);
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if let ForeignItem::Verbatim(tokens) = item {
            self.scan_tokens(tokens.clone());
        }
        visit::visit_foreign_item(self, item);
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

    fn visit_path(&mut self, path: &'ast Path) {
        let names: Vec<String> = path
            .segments
            .iter()
            .map(|s| s.ident.unraw().to_string())
            .collect();
        self.segments(&names);
        visit::visit_path(self, path);
    }

    fn visit_use_tree(&mut self, tree: &'ast UseTree) {
        if let UseTree::Rename(r) = tree {
            let name = r.ident.unraw().to_string();
            if BIND_TYPES.contains(&name.as_str()) || name == SOCKET_BUILDER {
                self.record(format!("use {name} as {}", r.rename.unraw()));
            }
        }
        visit::visit_use_tree(self, tree);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// Every bind form in the production syntax of `src`, by enclosing function
/// and counted form; a source that does not parse fails.
fn bind_sites(name: &str, src: &str) -> BTreeMap<(String, String), usize> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its bind sites cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut scan = Scan::default();
    if let Ok(file) = &parsed {
        scan.visit_file(file);
    }
    scan.sites
}

/// `sites` as a counted map, for fixture assertions.
fn counted(sites: &[(&str, &str, usize)]) -> BTreeMap<(String, String), usize> {
    sites
        .iter()
        .map(|(within, form, n)| (((*within).to_owned(), (*form).to_owned()), *n))
        .collect()
}

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must count or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_planted_bind_is_counted_under_its_function() {
    let src = r"
async fn listen(addr: SocketAddr) {
    let _ = tokio::net::TcpListener::bind(addr).await;
    let _ = ::std::net::UdpSocket::bind(addr);
}
impl App {
    fn open(&self) { let _ = TcpListener::bind(self.addr); }
}
";
    assert_eq!(
        bind_sites("fixture", src),
        counted(&[
            ("listen", "TcpListener::bind", 1),
            ("listen", "UdpSocket::bind", 1),
            ("open", "TcpListener::bind", 1),
        ])
    );
}

#[test]
fn a_bind_fn_pointer_a_socket_builder_and_an_alias_are_counted() {
    let src = r"
use tokio::net::TcpListener as Listener;
use std::net::{UdpSocket as U, TcpStream};
fn open() {
    let f = TcpListener::bind;
    let s = tokio::net::TcpSocket::new_v4();
    let _ = Listener::bind(addr);
}
";
    assert_eq!(
        bind_sites("fixture", src),
        counted(&[
            (MODULE_LEVEL, "use TcpListener as Listener", 1),
            (MODULE_LEVEL, "use UdpSocket as U", 1),
            ("open", "TcpListener::bind", 1),
            ("open", "TcpSocket", 1),
        ])
    );
}

#[test]
fn a_bind_inside_a_macro_body_is_counted() {
    let src = r#"
fn open() {
    let _ = format!("{:?}", std::net::TcpListener::bind("127.0.0.1:0"));
    m! { #[cfg(test)] fn t() { UdpSocket::bind(addr) } }
}
"#;
    assert_eq!(
        bind_sites("fixture", src),
        counted(&[
            ("open", "TcpListener::bind", 1),
            ("open", "UdpSocket::bind", 1),
        ])
    );
}

#[test]
fn test_only_code_strings_and_comments_are_not_counted() {
    let src = r#"
/// `TcpListener::bind` is prose.
fn open() {
    // UdpSocket::bind(addr)
    let s = "TcpListener::bind(addr)";
    #[cfg(test)]
    let t = TcpListener::bind(addr);
    let l: TcpListener = accept();
    let _ = (s, l);
}
#[cfg(test)]
mod tests {
    fn t() { let _ = std::net::TcpListener::bind("127.0.0.1:0"); }
}
#[cfg(all(test, feature = "debugger"))]
mod seam_tests {
    fn t() { let _ = std::net::TcpListener::bind("127.0.0.1:0"); }
}
"#;
    assert_eq!(bind_sites("fixture", src), BTreeMap::new());
}

// A `cfg` the stripper cannot prove test-only keeps the node scanned, so an
// unknown shape can turn the scan red but never hide a bind.
#[test]
fn a_cfg_not_proven_test_only_is_scanned() {
    let src = r#"
#[cfg(not(test))]
fn a() { let _ = TcpListener::bind(addr); }
#[cfg(any(test, feature = "server"))]
fn b() { let _ = TcpListener::bind(addr); }
#[cfg(feature = "test")]
fn c() { let _ = TcpListener::bind(addr); }
#[cfg(test_like_but_not_test)]
fn d() { let _ = TcpListener::bind(addr); }
#[cfg_attr(test, allow(dead_code))]
fn e() { let _ = TcpListener::bind(addr); }
"#;
    assert_eq!(
        bind_sites("fixture", src),
        counted(&[
            ("a", "TcpListener::bind", 1),
            ("b", "TcpListener::bind", 1),
            ("c", "TcpListener::bind", 1),
            ("d", "TcpListener::bind", 1),
            ("e", "TcpListener::bind", 1),
        ])
    );
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = bind_sites("fixture", "fn open( { TcpListener::bind(addr) }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// Every bind in the runtime's production code is an admitted site, at its
/// admitted count.
#[test]
fn every_bind_site_is_admitted() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in [
        "server.rs",
        "web/mod.rs",
        "control.rs",
        "web/console_proxy.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (name, src) in &sources {
        for ((within, form), count) in bind_sites(name, src) {
            found.insert((name.clone(), within, form), count);
        }
    }
    let admitted: BTreeMap<(String, String, String), usize> = ADMITTED
        .iter()
        .map(|(file, within, form, count)| {
            (
                ((*file).to_owned(), (*within).to_owned(), (*form).to_owned()),
                *count,
            )
        })
        .collect();
    assert_eq!(
        found, admitted,
        "a socket bind outside test code must be admitted in ADMITTED; an app listener \
         binds only through `server::bind_app_listener`"
    );
}

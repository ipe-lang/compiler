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
//! A node is skipped only when its `cfg` is proven test-only, so an
//! unrecognised shape keeps it scanned.
#![cfg(not(target_arch = "wasm32"))]

use syn::visit::{self, Visit};
use syn::{
    Attribute, Fields, GenericArgument, ItemEnum, ItemFn, ItemImpl, ItemMod, ItemStruct,
    PathArguments, Type,
};

// The `cfg` classification shared with the dial and print-macro scans; this
// scan needs only `cfg_test_only`.
#[allow(dead_code)] // the shared module's other classifiers serve the other scans
#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::cfg_test_only;

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
        let test_fn = node
            .attrs
            .iter()
            .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "test"));
        if !test_fn && !cfg_test_only(&node.attrs) {
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

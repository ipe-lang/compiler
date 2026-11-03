//! `Int` arithmetic scan: the runtime's arithmetic kernels never wrap, saturate
//! or cast an Ipê `Int`.
//!
//! An `Int` result outside the 64-bit range must trip `IntOverflow`, and every
//! numeric narrowing must go through the one narrowing home (`narrow.rs`). A
//! `wrapping_*`, `saturating_*` or `overflowing_*` name, or any `as` cast, in
//! the arithmetic kernels is the shape that silently yields a wrong number
//! instead. [`ARITH_FILES`] are parsed with `syn`, and each such shape is
//! counted per enclosing function in production syntax: a method call, a path
//! such as `i64::wrapping_add` or `<i64>::wrapping_add`, a `use` of the name,
//! a cast to any type (so a type alias cannot hide one), and the same
//! spellings inside a macro body. [`ADMITTED`] lists each `(file, fn, shape)`
//! with its exact count and why it never touches an Ipê value; an unlisted
//! site, a miscounted one and a stale entry all go red.
#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;

use proc_macro2::{TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprCast, ExprMethodCall, ImplItem, ImplItemFn, Item, ItemFn, Macro,
    Path, Stmt, TraitItem, TraitItemFn, Type, UseName, UseRename,
};

#[path = "support/cfg_scan.rs"]
mod cfg_scan;
use cfg_scan::{cfg_test_only, expr_attrs, impl_item_attrs, item_attrs, trait_item_attrs};

/// The runtime files that hold the `Int` arithmetic kernels.
///
/// `time.rs` holds the instant arithmetic (`Time.addMillis`, `diffDays`, ...)
/// and `web/transition.rs` the `Int` arms of the browser interpreter: each
/// yields an Ipê `Int` exactly as `math.rs` does. `string.rs` yields lengths
/// and indexes as Ipê `Int`s and reads counts and widths from them.
const ARITH_FILES: &[&str] = &[
    "math.rs",
    "basics.rs",
    "list.rs",
    "string.rs",
    "time.rs",
    "web/transition.rs",
];

/// The name a site written outside any function is keyed under.
const OUTSIDE_FN: &str = "<outside any fn>";

/// The method-name prefixes that wrap, saturate or flag instead of tripping.
const LOSSY_PREFIXES: &[&str] = &["wrapping_", "saturating_", "overflowing_"];

/// The shape a cast to `target` is recorded under.
fn cast_shape(target: &str) -> String {
    format!("as {target}")
}

/// A production site the scan admits, with the reason it is not an Ipê `Int`.
struct Admitted {
    file: &'static str,
    function: &'static str,
    shape: &'static str,
    count: usize,
    why: &'static str,
}

/// Every admitted lossy shape in [`ARITH_FILES`].
const ADMITTED: &[Admitted] = &[
    Admitted {
        file: "list.rs",
        function: "list_intersperse",
        shape: "saturating_mul",
        count: 1,
        why: "a `usize` capacity hint for the output `Vec`, never an Ipê value",
    },
    Admitted {
        file: "list.rs",
        function: "list_intersperse",
        shape: "saturating_sub",
        count: 1,
        why: "a `usize` capacity hint for the output `Vec`, never an Ipê value",
    },
    Admitted {
        file: "time.rs",
        function: "sleep_chunks",
        shape: "saturating_sub",
        count: 1,
        why: "the `u64` wait still owed after one timer chunk, never an Ipê value",
    },
    Admitted {
        file: "time.rs",
        function: "time_add_months",
        shape: "saturating_add",
        count: 2,
        why: "a month index and target year that a refused `i32` year parse turns \
              back; a saturated one never reaches the result",
    },
    Admitted {
        file: "time.rs",
        function: "time_add_years",
        shape: "saturating_mul",
        count: 1,
        why: "a month count `time_add_months` turns back through its `i32` year \
              parse; a saturated one never reaches the result",
    },
    Admitted {
        file: "time.rs",
        function: "time_days_in_month",
        shape: "saturating_add",
        count: 1,
        why: "the next `i32` calendar year; a saturated one has no date, so the \
              count is the refused `0`, never a saturated value",
    },
];

/// The lossy shape a name spells, if any.
fn lossy_shape(name: &str) -> Option<String> {
    LOSSY_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
        .then(|| name.to_owned())
}

/// The lossy sites of one source, as `(function, shape)` in source order.
#[derive(Default)]
struct Scan {
    functions: Vec<String>,
    sites: Vec<(String, String)>,
}

impl Scan {
    fn record(&mut self, shape: String) {
        let function = self
            .functions
            .last()
            .map_or_else(|| OUTSIDE_FN.to_owned(), Clone::clone);
        self.sites.push((function, shape));
    }

    /// Counts the lossy names and `as` casts of a token stream, recursing into
    /// groups: a macro body is scanned token by token.
    fn scan_tokens(&mut self, tokens: TokenStream) {
        let mut previous_as = false;
        for tree in tokens {
            match tree {
                TokenTree::Group(group) => {
                    if previous_as {
                        self.record(cast_shape("<group>"));
                    }
                    previous_as = false;
                    self.scan_tokens(group.stream());
                }
                TokenTree::Ident(ident) => {
                    let name = ident.unraw().to_string();
                    if previous_as {
                        self.record(cast_shape(&name));
                    }
                    if let Some(shape) = lossy_shape(&name) {
                        self.record(shape);
                    }
                    previous_as = name == "as";
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {
                    if previous_as {
                        self.record(cast_shape("<punct>"));
                    }
                    previous_as = false;
                }
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

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !cfg_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
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

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if let Some(shape) = lossy_shape(&call.method.unraw().to_string()) {
            self.record(shape);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        for segment in &path.segments {
            if let Some(shape) = lossy_shape(&segment.ident.unraw().to_string()) {
                self.record(shape);
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_expr_cast(&mut self, cast: &'ast ExprCast) {
        let target = match cast.ty.as_ref() {
            Type::Path(target) => target
                .path
                .segments
                .last()
                .map_or_else(|| "<path>".to_owned(), |s| s.ident.unraw().to_string()),
            _ => "<type>".to_owned(),
        };
        self.record(cast_shape(&target));
        visit::visit_expr_cast(self, cast);
    }

    fn visit_use_name(&mut self, name: &'ast UseName) {
        if let Some(shape) = lossy_shape(&name.ident.unraw().to_string()) {
            self.record(shape);
        }
    }

    fn visit_use_rename(&mut self, rename: &'ast UseRename) {
        if let Some(shape) = lossy_shape(&rename.ident.unraw().to_string()) {
            self.record(shape);
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        self.scan_tokens(mac.tokens.clone());
        visit::visit_macro(self, mac);
    }
}

/// The lossy sites of one source; a source that does not parse fails.
fn scan(name: &str, src: &str) -> Vec<(String, String)> {
    let parsed = syn::parse_file(src);
    assert!(
        parsed.is_ok(),
        "{name}: does not parse as Rust, so its arithmetic sites cannot be counted: {:?}",
        parsed.as_ref().err().map(ToString::to_string)
    );
    let mut walk = Scan::default();
    if let Ok(file) = parsed {
        walk.visit_file(&file);
    }
    walk.sites
}

/// Every difference between the lossy sites of `sources` and `admitted`.
fn violations(sources: &[(&str, &str)], admitted: &[Admitted]) -> Vec<String> {
    let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (file, src) in sources {
        for (function, shape) in scan(file, src) {
            let count = counts
                .entry(((*file).to_owned(), function, shape))
                .or_insert(0);
            *count = count.saturating_add(1);
        }
    }
    let mut out = Vec::new();
    for ((file, function, shape), count) in &counts {
        let listed = admitted.iter().find(|a| {
            a.file == file.as_str() && a.function == function.as_str() && a.shape == shape.as_str()
        });
        match listed {
            None => out.push(format!(
                "{file}: `{function}` uses `{shape}` {count} time(s) unadmitted: an Ipê `Int` \
                 result outside the 64-bit range must trip `IntOverflow` (a `Float` must narrow \
                 through `narrow.rs`), never wrap, saturate or cast"
            )),
            Some(site) if site.count != *count => out.push(format!(
                "{file}: `{function}` `{shape}` occurs {count} time(s), admitted {}",
                site.count
            )),
            Some(site) if site.why.trim().is_empty() => out.push(format!(
                "{file}: `{function}` must say why its `{shape}` is not an Ipê value"
            )),
            Some(_) => {}
        }
    }
    for site in admitted {
        let key = (
            site.file.to_owned(),
            site.function.to_owned(),
            site.shape.to_owned(),
        );
        if !counts.contains_key(&key) {
            out.push(format!(
                "{}: `{}` `{}` admitted {} time(s), found 0 (stale entry)",
                site.file, site.function, site.shape, site.count
            ));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Planted fixtures: the scan goes red on each lossy shape.
// ---------------------------------------------------------------------------

#[test]
fn a_planted_wrap_saturation_or_cast_is_refused() {
    let src = r"
pub fn ipe_int_add(a: i64, b: i64) -> i64 { a.wrapping_add(b) }
pub fn basics_negate(x: i64) -> i64 { i64::saturating_neg(x) }
pub fn list_sum(xs: Vec<i64>) -> i64 { xs.into_iter().fold(0, |a, x| a.overflowing_add(x).0) }
pub fn math_round(x: f64) -> i64 { x.round() as i64 }
pub fn in_macro(x: f64) -> String { format!({}, x as i64) }
type Int = i64;
pub fn via_alias(x: f64) -> Int { x as Int }
pub fn list_take(n: i64) -> usize { n as usize }
pub fn via_qself(a: i64) -> i64 { <i64>::wrapping_mul(a, 2) }
pub fn via_pointer(xs: Vec<i64>) -> i64 { xs.into_iter().fold(0, i64::wrapping_add) }
use some::wrapping_neg as neg;
use some::saturating_pow;
";
    let found = violations(&[("math.rs", src)], &[]);
    for (function, shape) in [
        ("ipe_int_add", "wrapping_add"),
        ("basics_negate", "saturating_neg"),
        ("list_sum", "overflowing_add"),
        ("math_round", "as i64"),
        ("in_macro", "as i64"),
        ("via_alias", "as Int"),
        ("list_take", "as usize"),
        ("via_qself", "wrapping_mul"),
        ("via_pointer", "wrapping_add"),
        (OUTSIDE_FN, "saturating_pow"),
        (OUTSIDE_FN, "wrapping_neg"),
    ] {
        assert!(
            found
                .iter()
                .any(|v| v.contains(&format!("`{function}` uses `{shape}`"))),
            "`{function}` `{shape}` must be refused: {found:#?}"
        );
    }
    assert_eq!(found.len(), 11, "{found:#?}");
}

#[test]
fn a_stale_or_miscounted_admission_is_refused() {
    let stale = violations(&[("list.rs", "fn list_intersperse() {}")], ADMITTED);
    assert!(
        stale.iter().any(|v| v.contains("(stale entry)")),
        "{stale:#?}"
    );
    let twice = r"
fn list_intersperse(n: usize) -> usize {
    n.saturating_mul(2).saturating_mul(2).saturating_sub(1)
}
";
    let miscounted = violations(&[("list.rs", twice)], ADMITTED);
    assert!(
        miscounted
            .iter()
            .any(|v| v.contains("`saturating_mul` occurs 2 time(s), admitted 1")),
        "{miscounted:#?}"
    );
}

#[test]
fn test_only_code_text_and_exact_names_are_not_sites() {
    let src = r#"
/// wrapping_add in a doc comment, `x as i64`.
// saturating_sub in a line comment.
fn text() -> &'static str { "wrapping_add as i64" }
fn exact(a: i64, b: i64) -> Option<i64> { a.checked_add(b) }
fn generic<T: IpeWrappingAdd>(a: T, b: T) -> T { a.ipe_wrapping_add(b) }
fn widen(n: i32) -> i64 { i64::from(n) }
fn narrowed(n: i64) -> usize { crate::narrow::count_from_int(n) }
#[cfg(test)]
mod tests { fn t() -> i64 { 1i64.wrapping_add(2) as i64 } }
"#;
    let found = violations(&[("plain.rs", src)], &[]);
    assert!(found.is_empty(), "{found:#?}");
}

// ---------------------------------------------------------------------------
// The scan over the arithmetic kernels.
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::expect_used)] // an unreadable kernel source must fail the scan, never be skipped
fn the_arithmetic_kernels_never_wrap_saturate_or_cast_an_int() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources: Vec<(&str, String)> = ARITH_FILES
        .iter()
        .map(|file| {
            let src = std::fs::read_to_string(root.join(file)).expect("read an arithmetic kernel");
            (*file, src)
        })
        .collect();
    let borrowed: Vec<(&str, &str)> = sources
        .iter()
        .map(|(file, src)| (*file, src.as_str()))
        .collect();
    let found = violations(&borrowed, ADMITTED);
    assert!(
        found.is_empty(),
        "Int arithmetic scan:\n{}",
        found.join("\n")
    );
}

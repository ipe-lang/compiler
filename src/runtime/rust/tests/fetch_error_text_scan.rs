//! Fetch error-text scan: the browser `fetch` path never renders a value it did not write.
//!
//! The body of `do_fetch` in `src/http_client.rs` is parsed with `syn`. It must
//! invoke no macro at all, so no formatting macro can interpolate a browser
//! error, URL, or header into an error string there, whatever name it is
//! reached by, and no macro body can hide code the scan cannot read. Every
//! `IpeResult::Err(..)` it builds must carry either a `FetchFailure` turned
//! into an error by `into_error()`, or the `body_refusal` the capped body
//! reader returned, whose texts are fixed. A shape the scan does not recognise
//! turns it red.
#![cfg(not(target_arch = "wasm32"))]

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, File, Item, ItemFn, Macro, Path};

/// The `http_client.rs` source the scan reads.
const HTTP_CLIENT: &str = include_str!("../src/http_client.rs");

/// The one binding that may pass straight into an `IpeResult::Err`.
const BODY_REFUSAL: &str = "body_refusal";

/// The binding a computed `FetchFailure` may be held in before `into_error`.
const FAILURE_BINDING: &str = "failure";

/// One finding the scan reports.
#[derive(Debug, PartialEq, Eq)]
enum Finding {
    /// A macro invocation inside `do_fetch`, by its last path segment.
    Macro(String),
    /// An `IpeResult::Err` argument that is not a fixed-text failure.
    UntypedErr,
}

/// Whether `path` names `segments` exactly, ignoring generic arguments.
fn path_is(path: &Path, segments: &[&str]) -> bool {
    path.segments.len() == segments.len()
        && path
            .segments
            .iter()
            .zip(segments)
            .all(|(segment, want)| segment.ident == want)
}

/// Whether `path` is `FetchFailure::<Variant>`.
fn is_fetch_failure_variant(path: &Path) -> bool {
    path.segments.len() == 2
        && path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == "FetchFailure")
}

/// Whether `path` is the single identifier `name`.
fn is_ident(path: &Path, name: &str) -> bool {
    path_is(path, &[name])
}

/// Whether `arg` is an admitted `IpeResult::Err` argument.
fn admitted_err_arg(arg: &Expr) -> bool {
    match arg {
        Expr::Path(path) => is_ident(&path.path, BODY_REFUSAL),
        Expr::MethodCall(call) if call.method == "into_error" && call.args.is_empty() => {
            match call.receiver.as_ref() {
                Expr::Path(path) => {
                    is_fetch_failure_variant(&path.path) || is_ident(&path.path, FAILURE_BINDING)
                }
                Expr::Call(inner) => match inner.func.as_ref() {
                    Expr::Path(path) => is_fetch_failure_variant(&path.path),
                    _ => false,
                },
                _ => false,
            }
        }
        _ => false,
    }
}

/// Collects findings over one function body.
#[derive(Default)]
struct BodyScan {
    findings: Vec<Finding>,
}

impl<'ast> Visit<'ast> for BodyScan {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        self.findings.push(Finding::Macro(name));
        visit::visit_macro(self, mac);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(func) = call.func.as_ref()
            && path_is(&func.path, &["IpeResult", "Err"])
        {
            let admitted = call.args.len() == 1 && call.args.first().is_some_and(admitted_err_arg);
            if !admitted {
                self.findings.push(Finding::UntypedErr);
            }
        }
        visit::visit_expr_call(self, call);
    }
}

/// Every function named `name` in `items`, nested modules included.
fn functions_named<'a>(items: &'a [Item], name: &str, out: &mut Vec<&'a ItemFn>) {
    for item in items {
        match item {
            Item::Fn(function) if function.sig.ident == name => out.push(function),
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    functions_named(nested, name, out);
                }
            }
            _ => {}
        }
    }
}

/// The outcome of scanning one source text.
#[derive(Debug, PartialEq, Eq)]
enum ScanOutcome {
    /// The source did not parse.
    Unparsed,
    /// The source holds a number of `do_fetch` functions other than one.
    NotExactlyOne(usize),
    /// The one `do_fetch` body, scanned.
    Scanned(Vec<Finding>),
}

/// Scans the `do_fetch` body of `source`.
fn scan(source: &str) -> ScanOutcome {
    let Ok(file) = syn::parse_str::<File>(source) else {
        return ScanOutcome::Unparsed;
    };
    let mut found = Vec::new();
    functions_named(&file.items, "do_fetch", &mut found);
    let [function] = found.as_slice() else {
        return ScanOutcome::NotExactlyOne(found.len());
    };
    let mut body = BodyScan::default();
    body.visit_block(&function.block);
    ScanOutcome::Scanned(body.findings)
}

#[test]
fn the_real_do_fetch_renders_no_foreign_text() {
    assert_eq!(scan(HTTP_CLIENT), ScanOutcome::Scanned(Vec::new()));
}

#[test]
fn a_debug_rendered_browser_error_trips_the_scan() {
    let source = r#"
        async fn do_fetch() -> IpeResult<E, R> {
            match go().await {
                Ok(v) => v,
                Err(e) => return IpeResult::Err(format!("http: fetch failed: {e:?}").into()),
            }
        }
    "#;
    let ScanOutcome::Scanned(findings) = scan(source) else {
        assert!(matches!(scan(source), ScanOutcome::Scanned(_)));
        return;
    };
    assert!(findings.contains(&Finding::Macro("format".to_owned())));
    assert!(findings.contains(&Finding::UntypedErr));
}

#[test]
fn a_formatting_macro_under_another_name_trips_the_scan() {
    let source = r#"
        async fn do_fetch() -> IpeResult<E, R> {
            use std::format as render;
            let shown = render!("{e:?}");
            ok_res(shown)
        }
    "#;
    assert_eq!(
        scan(source),
        ScanOutcome::Scanned(vec![Finding::Macro("render".to_owned())])
    );
}

#[test]
fn a_converted_foreign_error_trips_the_scan() {
    let source = r"
        async fn do_fetch() -> IpeResult<E, R> {
            let Err(e) = go() else { return ok() };
            IpeResult::Err(e.into())
        }
    ";
    let ScanOutcome::Scanned(findings) = scan(source) else {
        assert!(matches!(scan(source), ScanOutcome::Scanned(_)));
        return;
    };
    assert_eq!(findings, vec![Finding::UntypedErr]);
}

#[test]
fn a_fixed_text_failure_passes_the_scan() {
    let source = r"
        async fn do_fetch() -> IpeResult<E, R> {
            if a() { return IpeResult::Err(FetchFailure::NoWindow.into_error()); }
            if b() { return IpeResult::Err(FetchFailure::BadTimeout(r).into_error()); }
            let failure = FetchFailure::TimedOut;
            if c() { return IpeResult::Err(failure.into_error()); }
            IpeResult::Err(body_refusal)
        }
    ";
    assert_eq!(scan(source), ScanOutcome::Scanned(Vec::new()));
}

#[test]
fn a_missing_or_duplicated_do_fetch_trips_the_scan() {
    assert_eq!(scan("fn other() {}"), ScanOutcome::NotExactlyOne(0));
    assert_eq!(
        scan("fn do_fetch() {} mod m { fn do_fetch() {} }"),
        ScanOutcome::NotExactlyOne(2)
    );
}

//! `unsafe-convention` — surface every call to an `unsafe*` escape-hatch
//! function, so reaching for one is deliberate and visible in review.
//!
//! Ipê names its escape hatches with an `unsafe` prefix by convention (an
//! `Unsafe` module qualifier, or a bare `unsafeFrom…`). Such a call is
//! legitimate — the compiler accepts it — but a team wants each use flagged so it
//! is a conscious choice, not a silent one. That "flag the sanctioned-but-risky"
//! judgement is policy on valid code: a lint, not a type rule. It is advisory
//! (no `--fix`): removing an escape hatch is a design decision, never mechanical.

use ipe_diagnostics::Span;
use ipe_syntax::{Expr, Expr_};

use crate::finding::Finding;
use crate::rules::Ctx;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &ctx.ast.values {
        walk(ctx, &value.value.body, &mut findings);
    }
    findings
}

/// True when a reference names an escape hatch by the `unsafe` convention: an
/// `Unsafe`-qualified name (`Foo.Unsafe.fromRaw`), or a bare / qualified name
/// beginning `unsafe` (`unsafeFromInt`).
fn is_unsafe_ref(ctx: &Ctx, expr: &Expr) -> Option<String> {
    match &expr.value {
        Expr_::VarQual(module, name) => {
            let m = ctx.text(*module);
            let n = ctx.text(*name);
            if m.rsplit('.').next() == Some("Unsafe") || m == "Unsafe" || n.starts_with("unsafe") {
                Some(format!("{m}.{n}"))
            } else {
                None
            }
        }
        Expr_::VarLocal(name) => {
            let n = ctx.text(*name);
            n.starts_with("unsafe").then(|| n.to_owned())
        }
        _ => None,
    }
}

/// Walk an expression, reporting each `unsafe*` reference — whether called or
/// used bare — exactly once at its own span.
fn walk(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    if let Some(shown) = is_unsafe_ref(ctx, expr) {
        report(ctx, expr.span, &shown, out);
    }
    // A matched reference is a `VarQual`/`VarLocal` leaf with no sub-expressions,
    // so this descent reports it exactly once; a `Call` to an `unsafe*` callee
    // reaches the callee node through this recursion, never twice.
    walk_children(ctx, expr, out);
}

/// Report one `unsafe*` reference, spelled `shown`, at `span`.
fn report(ctx: &Ctx, span: Span, shown: &str, out: &mut Vec<Finding>) {
    out.push(ctx.advisory(
        "unsafe-convention",
        span,
        format!("`{shown}` is an escape hatch — its use bypasses a normal safety guarantee"),
        vec![
            "reach for an `unsafe*` / `.Unsafe` binding only when the invariant is checked \
             elsewhere; make the choice deliberate and reviewed"
                .to_owned(),
            "suppress: `-- ipe-lint: allow unsafe-convention`".to_owned(),
        ],
    ));
}

/// Recurse into every sub-expression of `expr`.
///
/// Every variant has its own arm, so a new child-bearing variant is a compile
/// error here rather than a subtree the rule silently never visits.
fn walk_children(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    match &expr.value {
        Expr_::Call(callee, args) => {
            walk(ctx, callee, out);
            for arg in args {
                walk(ctx, arg, out);
            }
        }
        Expr_::Case(scrut, arms) => {
            walk(ctx, scrut, out);
            for (_pat, body) in arms {
                walk(ctx, body, out);
            }
        }
        Expr_::Lambda(_params, body) => walk(ctx, body, out),
        Expr_::Binops(pairs, last) => {
            for (operand, _op) in pairs {
                walk(ctx, operand, out);
            }
            walk(ctx, last, out);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                walk(ctx, &binding.body, out);
            }
            walk(ctx, body, out);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, body) in branches {
                walk(ctx, cond, out);
                walk(ctx, body, out);
            }
            walk(ctx, otherwise, out);
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for item in items {
                walk(ctx, item, out);
            }
        }
        Expr_::Record(fields) => {
            for (_name, value) in fields {
                walk(ctx, value, out);
            }
        }
        Expr_::Access(base, _field) => walk(ctx, base, out),
        Expr_::Update(base, fields) => {
            // The updated record is a bare name, not an `Expr`: `walk` never
            // sees it, so it is checked here.
            let name = ctx.text(base.value);
            if name.starts_with("unsafe") {
                report(ctx, base.span, name, out);
            }
            for (_name, value) in fields {
                walk(ctx, value, out);
            }
        }
        // Leaves: bare references (reported at `walk`'s top), the `do` bind's
        // identity head, literals, and unit.
        Expr_::VarLocal(_)
        | Expr_::VarQual(..)
        | Expr_::TaskAndThen
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}

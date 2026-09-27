//! `simplify-map-identity` — `List.map identity xs` restates `xs`.
//!
//! Ported from elm-review-simplify's `List.map identity xs --> xs` check.
//! Mapping the identity function over a list changes nothing; the mapped list
//! is the argument. Only `List.map` reached through the `List.` qualifier is
//! matched, so an aliased import (`import List as L`) is a false negative, not
//! a false positive.

use ipe_syntax::{Expr, Expr_};

use crate::finding::Finding;
use crate::rules::{Ctx, visit_exprs};

/// True when `expr` is a bare reference to `Basics.identity`, qualified or not.
fn is_identity(ctx: &Ctx, expr: &Expr) -> bool {
    match &expr.value {
        Expr_::VarLocal(sym) => ctx.text(*sym) == "identity",
        Expr_::VarQual(module, sym) => {
            ctx.text(*module) == "Basics" && ctx.text(*sym) == "identity"
        }
        _ => false,
    }
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Call(callee, args) = &expr.value else {
            return;
        };
        let Expr_::VarQual(module, name) = &callee.value else {
            return;
        };
        if ctx.text(*module) != "List" || ctx.text(*name) != "map" {
            return;
        }
        let simpler = match args.as_slice() {
            [f] if is_identity(ctx, f) => "identity".to_owned(),
            [f, xs] if is_identity(ctx, f) => ctx.slice(xs.span).trim().to_owned(),
            _ => return,
        };
        findings.push(ctx.advisory(
            "simplify-map-identity",
            expr.span,
            "`List.map identity` changes nothing".to_owned(),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow simplify-map-identity`".to_owned(),
            ],
        ));
    });
    findings
}

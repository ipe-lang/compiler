//! `simplify-cons-append` — `[a] ++ xs` restates `a :: xs`.
//!
//! Ported from elm-review-simplify's `[ a ] ++ xs --> a :: xs` check. `++` on a
//! single-element list literal is exactly a `::`, without the extra list
//! wrapper. Only a single-operator `++` chain whose left operand is a
//! one-element list literal is matched.

use ipe_syntax::Expr_;

use crate::finding::Finding;
use crate::rules::{Ctx, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Binops(pairs, rhs) = &expr.value else {
            return;
        };
        let [(lhs, op)] = pairs.as_slice() else {
            return;
        };
        if ctx.text(op.value) != "++" {
            return;
        }
        let Expr_::List(items) = &lhs.value else {
            return;
        };
        let [single] = items.as_slice() else {
            return;
        };
        let head = ctx.slice(single.span).trim();
        let tail = ctx.slice(rhs.span).trim();
        findings.push(ctx.advisory(
            "simplify-cons-append",
            expr.span,
            "appending a single-element list restates a `::`".to_owned(),
            vec![
                format!("write `{head} :: {tail}`"),
                "suppress: `-- ipe-lint: allow simplify-cons-append`".to_owned(),
            ],
        ));
    });
    findings
}

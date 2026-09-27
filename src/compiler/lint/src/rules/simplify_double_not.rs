//! `simplify-double-not` — `not (not x)` restates `x`.
//!
//! Ported from elm-review-simplify's `not (not x) --> x` check. `not` negates
//! once; negating a negation is the identity, so the inner value is the whole
//! expression's value. Only a direct, fully-applied `not` call is matched — a
//! `not` reached through an alias or partial application is left alone.

use ipe_syntax::{Expr, Expr_};

use crate::finding::Finding;
use crate::rules::{Ctx, visit_exprs};

/// The argument of `expr`, when `expr` is a one-argument call to unqualified
/// `not`.
fn not_arg<'a>(ctx: &Ctx, expr: &'a Expr) -> Option<&'a Expr> {
    let Expr_::Call(callee, args) = &expr.value else {
        return None;
    };
    let [arg] = args.as_slice() else {
        return None;
    };
    let Expr_::VarLocal(name) = &callee.value else {
        return None;
    };
    (ctx.text(*name) == "not").then_some(arg)
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Some(outer_arg) = not_arg(ctx, expr) else {
            return;
        };
        let Some(inner) = not_arg(ctx, outer_arg) else {
            return;
        };
        let simpler = ctx.slice(inner.span).trim();
        findings.push(ctx.advisory(
            "simplify-double-not",
            expr.span,
            "`not (not x)` restates `x`".to_owned(),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow simplify-double-not`".to_owned(),
            ],
        ));
    });
    findings
}

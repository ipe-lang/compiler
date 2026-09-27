//! `no-redundant-cons` — `x :: [ a, b ]` restates `[ x, a, b ]`.
//!
//! Ported from truqu/elm-review-noredundantcons. Consing onto a list literal
//! is exactly that longer list literal, without the extra `::`. Only a
//! single-operator `::` chain whose right operand is a list literal is
//! matched — consing onto a name, a call, or another `::` chain is left
//! alone, since those are not literal-onto-literal.

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
        if ctx.text(op.value) != "::" {
            return;
        }
        let Expr_::List(items) = &rhs.value else {
            return;
        };
        let head = ctx.slice(lhs.span).trim();
        let mut elements = vec![head.to_owned()];
        elements.extend(
            items
                .iter()
                .map(|item| ctx.slice(item.span).trim().to_owned()),
        );
        let simpler = format!("[ {} ]", elements.join(", "));
        findings.push(ctx.advisory(
            "no-redundant-cons",
            expr.span,
            "consing onto a list literal restates a longer list literal".to_owned(),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow no-redundant-cons`".to_owned(),
            ],
        ));
    });
    findings
}

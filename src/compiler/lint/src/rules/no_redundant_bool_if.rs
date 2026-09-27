//! `no-redundant-bool-if` — an `if` whose branches are both `Bool` literals.
//!
//! `if ready then True else False` is `ready`; `if ready then False else True`
//! is `not ready`; two identical literal branches make the condition
//! irrelevant. Only a single `if … then … else` (no `else if`) is checked.

use ipe_syntax::Expr_;

use crate::finding::Finding;
use crate::rules::{Ctx, bool_literal, is_atom, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::If(branches, otherwise) = &expr.value else {
            return;
        };
        let [(cond, then_)] = branches.as_slice() else {
            return;
        };
        let (Some(then_lit), Some(else_lit)) =
            (bool_literal(ctx, then_), bool_literal(ctx, otherwise))
        else {
            return;
        };
        let cond_src = ctx.slice(cond.span).trim();
        let simpler = match (then_lit, else_lit) {
            (true, false) => cond_src.to_owned(),
            (false, true) if is_atom(cond) => format!("not {cond_src}"),
            (false, true) => format!("not ({cond_src})"),
            (true, true) => "True".to_owned(),
            (false, false) => "False".to_owned(),
        };
        findings.push(ctx.advisory(
            "no-redundant-bool-if",
            expr.span,
            "an `if` choosing between `Bool` literals restates its condition".to_owned(),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow no-redundant-bool-if`".to_owned(),
            ],
        ));
    });
    findings
}

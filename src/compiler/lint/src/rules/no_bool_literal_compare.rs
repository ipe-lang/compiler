//! `no-bool-literal-compare` — an `==` / `/=` comparison against a `True` or
//! `False` literal.
//!
//! `done == True` is `done`; `done == False` and `done /= True` are
//! `not done`. The comparison adds noise and reads as if the operand were not
//! already a `Bool`. Only a single-operator chain is checked, so the operand
//! the literal is compared against is unambiguous.

use ipe_syntax::Expr_;

use crate::finding::Finding;
use crate::rules::{Ctx, bool_literal, is_atom, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Binops(pairs, rhs) = &expr.value else {
            return;
        };
        let [(lhs, op)] = pairs.as_slice() else {
            return;
        };
        let equal = match ctx.text(op.value) {
            "==" => true,
            "/=" => false,
            _ => return,
        };
        let (literal, operand) = match (bool_literal(ctx, lhs), bool_literal(ctx, rhs)) {
            (Some(lit), None) => (lit, rhs.as_ref()),
            (None, Some(lit)) => (lit, lhs),
            _ => return,
        };
        let operand_src = ctx.slice(operand.span).trim();
        let simpler = if literal == equal {
            operand_src.to_owned()
        } else if is_atom(operand) {
            format!("not {operand_src}")
        } else {
            format!("not ({operand_src})")
        };
        findings.push(ctx.advisory(
            "no-bool-literal-compare",
            expr.span,
            "comparing a `Bool` against a `True` / `False` literal is redundant".to_owned(),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow no-bool-literal-compare`".to_owned(),
            ],
        ));
    });
    findings
}

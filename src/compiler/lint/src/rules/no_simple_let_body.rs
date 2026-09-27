//! `no-simple-let-body` — a `let` whose body only returns its last binding.
//!
//! `let total = a + b in total` is `a + b`: the final name adds a hop without
//! adding meaning. The rule fires only when the body is a bare reference to the
//! name the last binding introduces with a plain variable pattern.

use ipe_syntax::{Expr_, Pattern_};

use crate::finding::Finding;
use crate::rules::{Ctx, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Let(bindings, body) = &expr.value else {
            return;
        };
        let (Some(last), Expr_::VarLocal(used)) = (bindings.last(), &body.value) else {
            return;
        };
        let Pattern_::PVar(bound) = &last.pat.value else {
            return;
        };
        // `let f x = … in f` returns a named function; inlining it as a bare
        // lambda would not read better.
        if bound != used || matches!(last.body.value, Expr_::Lambda(..)) {
            return;
        }
        let name = ctx.text(*bound);
        findings.push(ctx.advisory(
            "no-simple-let-body",
            last.pat.span,
            format!("`{name}` is bound only to be returned"),
            vec![
                format!("return the expression bound to `{name}` directly"),
                "suppress: `-- ipe-lint: allow no-simple-let-body`".to_owned(),
            ],
        ));
    });
    findings
}

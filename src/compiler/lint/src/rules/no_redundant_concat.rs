//! `no-redundant-concat` — `List.concat [ xs ]` / `String.concat [ s ]` restate
//! their single element.
//!
//! Ported from elm-review's `NoRedundantConcat`. Flattening a one-element list
//! of lists (or of strings) is exactly that element; the `concat` call adds a
//! traversal without adding meaning. Only `List.concat` / `String.concat`
//! reached through their qualifier, applied to a list literal with exactly one
//! item, are matched.

use ipe_syntax::Expr_;

use crate::finding::Finding;
use crate::rules::{Ctx, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Call(callee, args) = &expr.value else {
            return;
        };
        let Expr_::VarQual(module, name) = &callee.value else {
            return;
        };
        let module = ctx.text(*module);
        if (module != "List" && module != "String") || ctx.text(*name) != "concat" {
            return;
        }
        let [arg] = args.as_slice() else {
            return;
        };
        let Expr_::List(items) = &arg.value else {
            return;
        };
        let [single] = items.as_slice() else {
            return;
        };
        let simpler = ctx.slice(single.span).trim();
        findings.push(ctx.advisory(
            "no-redundant-concat",
            expr.span,
            format!("`{module}.concat` of a single-element list restates that element"),
            vec![
                format!("write `{simpler}`"),
                "suppress: `-- ipe-lint: allow no-redundant-concat`".to_owned(),
            ],
        ));
    });
    findings
}

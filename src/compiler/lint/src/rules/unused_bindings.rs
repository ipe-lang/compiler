//! `unused-bindings` — a `let` binding whose name is never referenced in the
//! rest of the enclosing scope.
//!
//! `let x = expensive_computation` that nobody reads wastes work and clutters
//! the code. This rule walks every `Let` node in every value binding and flags
//! any binding whose name symbol does not appear in a `VarLocal` in the `let`
//! body or in subsequent binding bodies in the same `let` block.
//!
//! Conservative contract (no false positives):
//! - Only plain-variable bindings (`let x = …`) are checked; patterns with
//!   destructuring, wildcards, or aliases are skipped.
//! - A binding used only inside a nested lambda is counted as used.
//! - Bindings whose name starts with `_` (conventional "intentionally unused"
//!   prefix) are never flagged.

use std::collections::HashSet;

use ipe_intern::Symbol;
use ipe_syntax::{Expr, Expr_, LetBinding, Pattern_};

use crate::finding::{Finding, Fix};
use crate::rules::Ctx;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &ctx.ast.values {
        walk_expr(ctx, &value.value.body, &mut findings);
    }
    findings
}

fn walk_expr(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    match &expr.value {
        Expr_::Let(bindings, body) => {
            check_let(ctx, bindings, body, out);
            walk_expr(ctx, body, out);
        }
        Expr_::Call(callee, args) => {
            walk_expr(ctx, callee, out);
            for a in args {
                walk_expr(ctx, a, out);
            }
        }
        Expr_::Case(scrut, arms) => {
            walk_expr(ctx, scrut, out);
            for (_, body) in arms {
                walk_expr(ctx, body, out);
            }
        }
        Expr_::Lambda(_, body) => walk_expr(ctx, body, out),
        Expr_::Binops(pairs, last) => {
            for (e, _) in pairs {
                walk_expr(ctx, e, out);
            }
            walk_expr(ctx, last, out);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, then_) in branches {
                walk_expr(ctx, cond, out);
                walk_expr(ctx, then_, out);
            }
            walk_expr(ctx, otherwise, out);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                walk_expr(ctx, e, out);
            }
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                walk_expr(ctx, v, out);
            }
        }
        // `Update` base is `Located<Symbol>` (a bare variable), not an Expr.
        Expr_::Update(_base, fields) => {
            for (_, v) in fields {
                walk_expr(ctx, v, out);
            }
        }
        Expr_::Access(rec, _) => walk_expr(ctx, rec, out),
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}

fn check_let(ctx: &Ctx, bindings: &[LetBinding], body: &Expr, out: &mut Vec<Finding>) {
    for (i, binding) in bindings.iter().enumerate() {
        let Pattern_::PVar(name_sym) = &binding.pat.value else {
            walk_expr(ctx, &binding.body, out);
            continue;
        };

        let name = ctx.text(*name_sym);
        if name.starts_with('_') {
            walk_expr(ctx, &binding.body, out);
            continue;
        }

        let mut used: HashSet<Symbol> = HashSet::new();
        for later in bindings.iter().skip(i + 1) {
            collect_used(&later.body, &mut used);
        }
        collect_used(body, &mut used);

        if !used.contains(name_sym) {
            out.push(ctx.with_fix(
                "unused-bindings",
                binding.pat.span,
                format!("`{name}` is bound but never used"),
                vec![
                    "remove the binding or prefix the name with `_` to silence this warning"
                        .to_owned(),
                    "suppress: `-- ipe-lint: allow unused-bindings`".to_owned(),
                ],
                Fix {
                    describe: "prefix the binding with `_`".to_owned(),
                    span: binding.pat.span,
                    replacement: format!("_{name}"),
                },
            ));
        }
        walk_expr(ctx, &binding.body, out);
    }
}

fn collect_used(expr: &Expr, used: &mut HashSet<Symbol>) {
    match &expr.value {
        Expr_::VarLocal(sym) => {
            used.insert(*sym);
        }
        Expr_::Call(callee, args) => {
            collect_used(callee, used);
            for a in args {
                collect_used(a, used);
            }
        }
        Expr_::Case(scrut, arms) => {
            collect_used(scrut, used);
            for (_, body) in arms {
                collect_used(body, used);
            }
        }
        Expr_::Lambda(_, body) => collect_used(body, used),
        Expr_::Binops(pairs, last) => {
            for (e, _) in pairs {
                collect_used(e, used);
            }
            collect_used(last, used);
        }
        Expr_::Let(inner_bindings, inner_body) => {
            for b in inner_bindings {
                collect_used(&b.body, used);
            }
            collect_used(inner_body, used);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, then_) in branches {
                collect_used(cond, used);
                collect_used(then_, used);
            }
            collect_used(otherwise, used);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                collect_used(e, used);
            }
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                collect_used(v, used);
            }
        }
        Expr_::Update(base, fields) => {
            // `{ base | … }` reads `base` — a use of that binding, not just the
            // updated fields. Dropping it falsely flags `x` unused in
            // `let x = … in { x | f = 1 }`.
            used.insert(base.value);
            for (_, v) in fields {
                collect_used(v, used);
            }
        }
        Expr_::Access(rec, _) => collect_used(rec, used),
        Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}

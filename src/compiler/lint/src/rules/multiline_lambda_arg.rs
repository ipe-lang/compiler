//! `multiline-lambda-arg` — a lambda spanning several lines passed inline as a
//! call argument.
//!
//! `List.map (\row ->` followed by a multi-line body hides the call's shape
//! behind the lambda's. Binding the lambda by name first — `let fmt = \row -> …
//! in List.map fmt rows`, or a `let` statement in a `do` block — lets the call
//! read in one line and names what the step does.
//!
//! Only lambdas that are genuine arguments of a source application are checked
//! (see [`crate::rules::is_source_call`]): the continuation lambda a `do`-block
//! `x <- task` desugars into is never reported, and neither is a lambda passed
//! with `<|` (`Task.andThen <| \x -> …`), which is an operator operand, not an
//! argument. A lambda that fits on one line is left alone.

use ipe_syntax::Expr_;

use crate::finding::Finding;
use crate::rules::{Ctx, is_source_call, visit_exprs};

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    visit_exprs(ctx, &mut |expr| {
        let Expr_::Call(_callee, args) = &expr.value else {
            return;
        };
        if !is_source_call(expr) {
            return;
        }
        for arg in args {
            if matches!(arg.value, Expr_::Lambda(..)) && ctx.slice(arg.span).contains('\n') {
                findings.push(ctx.advisory(
                    "multiline-lambda-arg",
                    arg.span,
                    "a multi-line lambda passed inline hides the call's shape".to_owned(),
                    vec![
                        "bind it by name first — `let step = \\x -> … in f step xs` \
                         (or a `let` statement in a `do` block) — and pass the name"
                            .to_owned(),
                        "suppress: `-- ipe-lint: allow multiline-lambda-arg`".to_owned(),
                    ],
                ));
            }
        }
    });
    findings
}

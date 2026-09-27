//! `no-missing-type-annotation` — a top-level declaration with no `: T`
//! signature.
//!
//! Ported from elm-review's `NoMissingTypeAnnotation`. Inference fills the gap
//! either way, so this is a house-style choice, not a soundness concern — it
//! ships `Allow` by default and only reports once a project opts in via
//! `lint.ipe`. Only top-level module declarations are checked; a `let`-local
//! binding's type is usually obvious from its narrow scope and is left alone.

use crate::finding::Finding;
use crate::rules::Ctx;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &ctx.ast.values {
        if value.value.type_annotation.is_some() {
            continue;
        }
        let name = ctx.text(value.value.name.value);
        findings.push(ctx.advisory(
            "no-missing-type-annotation",
            value.value.name.span,
            format!("`{name}` has no type annotation"),
            vec![
                format!("add a `{name} : T` signature above the definition"),
                "suppress: `-- ipe-lint: allow no-missing-type-annotation`".to_owned(),
            ],
        ));
    }
    findings
}

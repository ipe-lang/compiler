//! `unused-imports` — an import declaration whose bound names never appear in
//! the module body.
//!
//! An import introduces names in two ways:
//! 1. A module qualifier — either the `as Alias` alias or, absent that, the
//!    last segment of the dotted module name (`import Ipe.Url` → qualifier
//!    `Url`). This qualifier appears as the first symbol in `VarQual` or as
//!    the non-empty qualifier field in `TType` annotations.
//! 2. Explicitly exposed names: `import Foo exposing (bar, Baz)` — each name
//!    is bound unqualified and may appear as `VarLocal` or a bare type name.
//!
//! `exposing (..)` is a wildcard: the complete exported surface is not known
//! at the parse level, so a wildcard import is conservatively treated as used
//! (never flagged as unused).
//!
//! A name listed in the module's own `exposing` clause is a re-export — it is
//! treated as used so imports that exist solely to re-export are not flagged.
//!
//! This rule is deliberately conservative: when in doubt it does not fire.

use std::collections::HashSet;

use ipe_intern::Symbol;
use ipe_syntax::{Exposing, Expr, Expr_, Pattern, Pattern_, TypeAnnotation};

use crate::finding::Finding;
use crate::rules::Ctx;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut used_qualifiers: HashSet<Symbol> = HashSet::new();
    let mut used_unqualified: HashSet<Symbol> = HashSet::new();

    // Walk all value bodies and their type annotations.
    for value in &ctx.ast.values {
        walk_expr(
            &value.value.body,
            &mut used_qualifiers,
            &mut used_unqualified,
        );
        if let Some(ann) = &value.value.type_annotation {
            walk_type(&ann.value, &mut used_qualifiers, &mut used_unqualified);
        }
    }
    // Union constructor argument types.
    for union in &ctx.ast.unions {
        for ctor in &union.value.ctors {
            for arg in &ctor.value.args {
                walk_type(arg, &mut used_qualifiers, &mut used_unqualified);
            }
        }
    }
    // Type alias bodies.
    for alias in &ctx.ast.aliases {
        walk_type(
            &alias.value.body.value,
            &mut used_qualifiers,
            &mut used_unqualified,
        );
    }
    // Re-exports: names in the module's own `exposing` list that came from
    // imports are treated as used so re-exporting imports are not flagged.
    if let Exposing::List(items) = &ctx.ast.exposing.value {
        use ipe_syntax::Exposed;
        for item in items {
            let sym = match &item.value {
                Exposed::Value(s) | Exposed::Type(s, _) => *s,
            };
            used_unqualified.insert(sym);
        }
    }

    let mut findings = Vec::new();
    'import: for import in &ctx.ast.imports {
        // `imports` is `Vec<Import>` (not `Vec<Located<Import>>`), so no `.value`.

        // Wildcard exposing — conservatively skip (cannot know what it binds).
        if matches!(&import.exposing.value, Exposing::All) {
            continue 'import;
        }

        // The qualifier this import introduces: `as Alias` if present, else the
        // last segment of the dotted module name.
        let qualifier: Option<Symbol> = import.alias.or_else(|| import.name.value.last().copied());
        if qualifier.is_some_and(|q| used_qualifiers.contains(&q)) {
            continue 'import;
        }

        // Check whether any explicitly exposed name is used.
        if let Exposing::List(items) = &import.exposing.value {
            use ipe_syntax::Exposed;
            for item in items {
                let sym = match &item.value {
                    Exposed::Value(s) | Exposed::Type(s, _) => *s,
                };
                if used_unqualified.contains(&sym) {
                    continue 'import;
                }
            }
        }

        // No introduced name was used anywhere in the module body.
        let module_text: String = import
            .name
            .value
            .iter()
            .map(|s| ctx.text(*s))
            .collect::<Vec<_>>()
            .join(".");
        findings.push(ctx.advisory(
            "unused-imports",
            import.span,
            format!("`import {module_text}` is never used in this module"),
            vec![
                "remove the import or add an `exposing` clause for the names you need".to_owned(),
                "suppress: `-- ipe-lint: allow unused-imports`".to_owned(),
            ],
        ));
    }
    findings
}

fn walk_expr(expr: &Expr, qualifiers: &mut HashSet<Symbol>, unqualified: &mut HashSet<Symbol>) {
    match &expr.value {
        Expr_::VarLocal(sym) => {
            unqualified.insert(*sym);
        }
        Expr_::VarQual(module_sym, _) => {
            qualifiers.insert(*module_sym);
        }
        Expr_::Call(callee, args) => {
            walk_expr(callee, qualifiers, unqualified);
            for arg in args {
                walk_expr(arg, qualifiers, unqualified);
            }
        }
        Expr_::Case(scrut, arms) => {
            walk_expr(scrut, qualifiers, unqualified);
            for (pat, body) in arms {
                walk_pattern(pat, qualifiers, unqualified);
                walk_expr(body, qualifiers, unqualified);
            }
        }
        Expr_::Lambda(pats, body) => {
            for p in pats {
                walk_pattern(p, qualifiers, unqualified);
            }
            walk_expr(body, qualifiers, unqualified);
        }
        Expr_::Binops(pairs, last) => {
            for (e, _op) in pairs {
                walk_expr(e, qualifiers, unqualified);
            }
            walk_expr(last, qualifiers, unqualified);
        }
        Expr_::Let(bindings, body) => {
            for b in bindings {
                walk_expr(&b.body, qualifiers, unqualified);
            }
            walk_expr(body, qualifiers, unqualified);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, then_) in branches {
                walk_expr(cond, qualifiers, unqualified);
                walk_expr(then_, qualifiers, unqualified);
            }
            walk_expr(otherwise, qualifiers, unqualified);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                walk_expr(e, qualifiers, unqualified);
            }
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                walk_expr(v, qualifiers, unqualified);
            }
        }
        // `Update` base is a `Located<Symbol>` (a bare variable name) — a use of
        // that name, so an unqualified import of the same name counts as used.
        Expr_::Update(base_sym, fields) => {
            unqualified.insert(base_sym.value);
            for (_, v) in fields {
                walk_expr(v, qualifiers, unqualified);
            }
        }
        Expr_::Access(rec, _) => walk_expr(rec, qualifiers, unqualified),
        // `::` is represented as `Binops` with the `::` operator symbol — no
        // separate `Cons` variant exists at the syntax level.
        Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::PathLit(_)
        | Expr_::Unit => {}
    }
}

fn walk_pattern(
    pat: &Pattern,
    qualifiers: &mut HashSet<Symbol>,
    unqualified: &mut HashSet<Symbol>,
) {
    match &pat.value {
        // `PCtor(name, module_segs, sub_pats)` — module_segs is non-empty for
        // qualified constructors like `Result.Ok`.
        Pattern_::PCtor(_name, module_segs, sub_pats) => {
            // If there are module segments, the first is the qualifier reference.
            if let Some(first_seg) = module_segs.first() {
                qualifiers.insert(*first_seg);
            }
            for sp in sub_pats {
                walk_pattern(sp, qualifiers, unqualified);
            }
        }
        Pattern_::PTuple(ps) | Pattern_::PList(ps) => {
            for p in ps {
                walk_pattern(p, qualifiers, unqualified);
            }
        }
        Pattern_::PCons(h, t) => {
            walk_pattern(h, qualifiers, unqualified);
            walk_pattern(t, qualifiers, unqualified);
        }
        // `PRecord` fields are `Vec<Located<Symbol>>` — just field names bound
        // as variables; no sub-patterns.
        Pattern_::PRecord(_field_names) => {}
        Pattern_::PVar(sym) => {
            unqualified.insert(*sym);
        }
        Pattern_::PAlias(inner, _) => walk_pattern(inner, qualifiers, unqualified),
        Pattern_::POr(alts) => {
            for alt in alts {
                walk_pattern(alt, qualifiers, unqualified);
            }
        }
        Pattern_::PAnything
        | Pattern_::PDebugAnything
        | Pattern_::PUnit
        | Pattern_::PInt(_)
        | Pattern_::PBool(_)
        | Pattern_::PStr(_)
        | Pattern_::PChar(_) => {}
    }
}

fn walk_type(
    ann: &TypeAnnotation,
    qualifiers: &mut HashSet<Symbol>,
    unqualified: &mut HashSet<Symbol>,
) {
    match ann {
        TypeAnnotation::TLambda(a, b) => {
            walk_type(a, qualifiers, unqualified);
            walk_type(b, qualifiers, unqualified);
        }
        TypeAnnotation::TVar(_) | TypeAnnotation::TUnit => {}
        TypeAnnotation::TType(qualifier_sym, segments, args) => {
            // Record the qualifier symbol (may be the empty sentinel — we record
            // it anyway; the import check compares against actual interned
            // qualifier/alias symbols, which are non-empty).
            qualifiers.insert(*qualifier_sym);
            // Also record the first segment as a potential unqualified name
            // (for `exposing`-imported types used bare).
            if let Some(first) = segments.first() {
                unqualified.insert(*first);
            }
            for arg in args {
                walk_type(arg, qualifiers, unqualified);
            }
        }
        TypeAnnotation::TTuple(ts) => {
            for t in ts {
                walk_type(t, qualifiers, unqualified);
            }
        }
        TypeAnnotation::TRecord(fields) | TypeAnnotation::TRecordOpen(_, fields) => {
            for (_, t) in fields {
                walk_type(t, qualifiers, unqualified);
            }
        }
    }
}

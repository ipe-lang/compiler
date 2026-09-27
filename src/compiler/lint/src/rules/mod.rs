//! The shipped rule set and the shared walk context.
//!
//! Every rule is a pure function `Ctx -> Vec<Finding>`. [`run_all`] invokes each
//! shipped rule in registry order and concatenates the results; the engine
//! ([`crate::run`]) then filters by configured severity and inline suppression
//! and sorts. Rules never mutate the AST or the source — a rewrite is expressed
//! only as a [`crate::Fix`] the engine applies later.
//!
//! # elm-review catalogue
//!
//! elm-review is the reference rule set for the Elm family. A rule is ported
//! when it is cheap (one syntactic match, no type information) and precise (no
//! false positive on idiomatic Ipê); otherwise it is rejected with the reason,
//! or listed as a remaining candidate.
//!
//! | elm-review rule | Ipê status |
//! | --- | --- |
//! | `NoBooleanCase`, `Simplify` (`if c then True else False`) | ported: `no-redundant-bool-if` |
//! | `Simplify` (`x == True`, `x /= False`) | ported: `no-bool-literal-compare` |
//! | `NoSimpleLetBody` | ported: `no-simple-let-body` |
//! | `NoUnused.Imports`, `NoUnused.Variables` (let bindings) | covered: `unused-imports`, `unused-bindings` |
//! | `NoDebug.Log`, `NoDebug.TodoOrToString` | rejected: the compiler already refuses `Debug.*` in a release build (IPE-L0140) |
//! | `NoSinglePatternCase` | rejected: `let` does not destructure, so a one-arm `case` is the only destructuring form |
//! | `NoExposingEverything`, `NoImportingEverything` | rejected: `import X exposing (..)` is idiomatic in every example's `package.ipe` manifest — a blanket rule misfires across the whole example corpus with no `package.ipe`-shaped allowance to except it |
//! | `NoMissingTypeAnnotation` | ported: `no-missing-type-annotation`, `Allow` by default (opt in via `lint.ipe`) |
//! | `Simplify` (`[a] ++ xs` → `a :: xs`) | ported: `simplify-cons-append` |
//! | `Simplify` (`List.map identity xs` → `xs`) | ported: `simplify-map-identity` |
//! | `Simplify` (`not (not x)` → `x`) | ported: `simplify-double-not` |
//! | `NoRedundantConcat` | ported: `no-redundant-concat` |
//! | `NoRedundantCons` | ported: `no-redundant-cons` |
//! | `NoUnused.Parameters`, `NoUnused.Patterns` | remaining: needs a general recursive pattern-variable collector (`unused-bindings` only walks flat `PVar` `let` binders); a parameter conventionally kept for interface clarity also risks false positives |
//! | `NoPrematureLetComputation` | remaining: needs a branch-usage analysis |
//! | `NoRecursiveUpdate`, `NoMissingSubscriptionsCall` | remaining: needs TEA-shape knowledge per app kind |
//! | `NoUnused.Exports`, `NoUnused.CustomTypeConstructors`, `NoUnused.Dependencies` | remaining: whole-project passes (cross-module engine) |

mod adjacent_bools;
mod multiline_lambda_arg;
mod no_bool_literal_compare;
mod no_empty_icon_button_label;
mod no_missing_type_annotation;
mod no_redundant_bool_if;
mod no_redundant_concat;
mod no_redundant_cons;
mod no_silent_outline_none;
mod no_simple_let_body;
mod prefer_pipeline;
mod prim_param;
mod simplify_cons_append;
mod simplify_double_not;
mod simplify_map_identity;
mod unsafe_convention;
mod unused_bindings;
mod unused_imports;
mod wrapper_consistency;
mod wrapper_consistency_cross;

#[cfg(test)]
mod simplify_tests;
#[cfg(test)]
mod style_tests;

use ipe_diagnostics::{Located, Span};
use ipe_intern::{Interner, Symbol};
use ipe_syntax::{Expr, Expr_, Module, TypeAnnotation, Value};

use crate::finding::{Finding, SigFix};

/// The read-only context every rule shares for one module: its path, its source
/// text (for span-based `--fix` slicing), the interner that parsed it, and the
/// parsed AST.
pub struct Ctx<'a> {
    /// The owning module's dotted path segments.
    pub module: &'a [String],
    /// The module's full source text.
    pub source: &'a str,
    /// The interner used to parse this module — resolves every [`Symbol`].
    pub interner: &'a Interner,
    /// The parsed module AST.
    pub ast: &'a Module,
}

impl Ctx<'_> {
    /// Resolve a [`Symbol`] to its interned text, or `""` when unresolvable
    /// (never expected for a parser-produced symbol).
    pub fn text(&self, sym: Symbol) -> &str {
        self.interner.resolve(sym).unwrap_or("")
    }

    /// A finding for this module carrying no fix.
    pub fn advisory(
        &self,
        rule: &'static str,
        span: Span,
        message: String,
        help: Vec<String>,
    ) -> Finding {
        Finding {
            rule,
            module: self.module.to_vec(),
            span,
            message,
            help,
            fix: None,
            sig_fix: None,
        }
    }

    /// A finding that carries a cross-module signature fix.
    pub fn with_sig_fix(
        &self,
        rule: &'static str,
        span: Span,
        message: String,
        help: Vec<String>,
        sig_fix: SigFix,
    ) -> Finding {
        Finding {
            rule,
            module: self.module.to_vec(),
            span,
            message,
            help,
            fix: None,
            sig_fix: Some(sig_fix),
        }
    }

    /// The source slice for `span`, or `""` for an out-of-range / non-boundary
    /// range (never panics).
    pub fn slice(&self, span: Span) -> &str {
        let lo = span.lo as usize;
        let hi = span.hi as usize;
        if lo > hi {
            return "";
        }
        self.source.get(lo..hi).unwrap_or("")
    }
}

/// Run every shipped single-module rule over `ctx`, in registry order.
pub fn run_all(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(prim_param::check(ctx));
    findings.extend(adjacent_bools::check(ctx));
    findings.extend(wrapper_consistency::check(ctx));
    findings.extend(unsafe_convention::check(ctx));
    findings.extend(prefer_pipeline::check(ctx));
    findings.extend(unused_imports::check(ctx));
    findings.extend(unused_bindings::check(ctx));
    findings.extend(no_silent_outline_none::check(ctx));
    findings.extend(no_empty_icon_button_label::check(ctx));
    findings.extend(multiline_lambda_arg::check(ctx));
    findings.extend(no_bool_literal_compare::check(ctx));
    findings.extend(no_redundant_bool_if::check(ctx));
    findings.extend(no_simple_let_body::check(ctx));
    findings.extend(simplify_double_not::check(ctx));
    findings.extend(simplify_map_identity::check(ctx));
    findings.extend(simplify_cons_append::check(ctx));
    findings.extend(no_redundant_cons::check(ctx));
    findings.extend(no_redundant_concat::check(ctx));
    findings.extend(no_missing_type_annotation::check(ctx));
    findings
}

/// True when `expr` is a function application the author wrote.
///
/// The parser spans a source call from its callee through its last argument,
/// with every child in source order inside it. Desugared calls break that
/// shape: a `do`-block `x <- task` becomes `Task.andThen (\x -> rest) task`
/// spanned on the `<-` token, with the lambda zero-width and the task after it,
/// and a restamped `do` block carries the `do` keyword's span. Rules that
/// reason about how a call reads test this before treating a `Call` node as
/// source.
pub fn is_source_call(expr: &Expr) -> bool {
    let Expr_::Call(callee, args) = &expr.value else {
        return false;
    };
    if callee.span.lo < expr.span.lo || callee.span.hi <= callee.span.lo {
        return false;
    }
    let mut prev_hi = callee.span.hi;
    for arg in args {
        if arg.span.lo < prev_hi || arg.span.hi <= arg.span.lo {
            return false;
        }
        prev_hi = arg.span.hi;
    }
    prev_hi <= expr.span.hi
}

/// True when `expr` is self-delimiting, so `not` can prefix it without parens.
pub const fn is_atom(expr: &Expr) -> bool {
    matches!(
        expr.value,
        Expr_::VarLocal(_)
            | Expr_::VarQual(_, _)
            | Expr_::Access(..)
            | Expr_::Int(_)
            | Expr_::Float(_)
            | Expr_::Str(_)
            | Expr_::Char(_)
            | Expr_::Unit
            | Expr_::Tuple(_)
            | Expr_::List(_)
            | Expr_::Record(_)
            | Expr_::Update(..)
    )
}

/// Visit every expression in every value body, parents before children.
pub fn visit_exprs(ctx: &Ctx, f: &mut impl FnMut(&Expr)) {
    for value in &ctx.ast.values {
        visit_expr(&value.value.body, f);
    }
}

fn visit_expr(expr: &Expr, f: &mut impl FnMut(&Expr)) {
    f(expr);
    match &expr.value {
        Expr_::Call(callee, args) => {
            visit_expr(callee, f);
            for arg in args {
                visit_expr(arg, f);
            }
        }
        Expr_::Case(scrut, arms) => {
            visit_expr(scrut, f);
            for (_pat, body) in arms {
                visit_expr(body, f);
            }
        }
        Expr_::Lambda(_, body) | Expr_::Access(body, _) => visit_expr(body, f),
        Expr_::Binops(pairs, last) => {
            for (operand, _op) in pairs {
                visit_expr(operand, f);
            }
            visit_expr(last, f);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                visit_expr(&binding.body, f);
            }
            visit_expr(body, f);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, body) in branches {
                visit_expr(cond, f);
                visit_expr(body, f);
            }
            visit_expr(otherwise, f);
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for item in items {
                visit_expr(item, f);
            }
        }
        Expr_::Record(fields) | Expr_::Update(_, fields) => {
            for (_name, value) in fields {
                visit_expr(value, f);
            }
        }
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::PathLit(_)
        | Expr_::Unit => {}
    }
}

/// The Bool literal `expr` denotes, if it is a bare `True` / `False`.
pub fn bool_literal(ctx: &Ctx, expr: &Expr) -> Option<bool> {
    match &expr.value {
        Expr_::VarLocal(sym) => match ctx.text(*sym) {
            "True" => Some(true),
            "False" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Run cross-module rules that require all modules simultaneously.
/// Called once per lint run after all per-module passes complete.
pub fn run_cross_module<'a>(ctxs: &[&'a Ctx<'a>]) -> Vec<Finding> {
    wrapper_consistency_cross::check_cross(ctxs)
}

/// True when `name` appears in the module's `exposing (...)` list (or the list
/// is `exposing (..)`). Rules that reason about the API edge use this to look
/// only at exported bindings — a private helper's bare primitive is nobody's
/// business.
pub fn is_exported(ctx: &Ctx, name: Symbol) -> bool {
    use ipe_syntax::{Exposed, Exposing};
    match &ctx.ast.exposing.value {
        Exposing::All => true,
        Exposing::List(items) => items.iter().any(|item| match &item.value {
            Exposed::Value(sym) => *sym == name,
            Exposed::Type(..) => false,
        }),
    }
}

/// Flatten a curried arrow type into its parameter types and its result type.
///
/// `A -> B -> C` yields params `[A, B]` and result `C`. A non-arrow type yields
/// an empty parameter list and itself as the result.
pub fn flatten_arrow(ann: &TypeAnnotation) -> (Vec<&TypeAnnotation>, &TypeAnnotation) {
    let mut params = Vec::new();
    let mut cursor = ann;
    while let TypeAnnotation::TLambda(arg, rest) = cursor {
        params.push(arg.as_ref());
        cursor = rest.as_ref();
    }
    (params, cursor)
}

/// The head constructor name of a type annotation, unqualified (`Int`, `Bool`,
/// `Port`), or `None` when the annotation is not a bare type constructor (an
/// arrow, a tuple, a record, or a type variable).
pub fn con_head_name<'a>(ctx: &'a Ctx, ann: &TypeAnnotation) -> Option<&'a str> {
    match ann {
        TypeAnnotation::TType(_qualifier, segments, args) if args.is_empty() => {
            segments.last().map(|s| ctx.text(*s))
        }
        _ => None,
    }
}

/// Each top-level value binding that carries a type annotation, as
/// `(value, annotation)`. The common driver for the signature-shape rules.
pub fn annotated_values<'a>(
    ctx: &'a Ctx,
) -> impl Iterator<Item = (&'a Located<Value>, &'a Located<TypeAnnotation>)> {
    ctx.ast
        .values
        .iter()
        .filter_map(|value| value.value.type_annotation.as_ref().map(|ann| (value, ann)))
}

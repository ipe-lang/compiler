//! Widget-file collection for the `CustomElement.fromFile "<js-path>"` constructor.
//!
//! The constructor's shape gate (single string literal) and its path seal (an
//! all-targets clean + traversal check, reusing `ipe_path_core`) run in canon,
//! where they are pure. The remaining check — that the named JS file actually EXISTS
//! inside the project root — needs the filesystem and the project root, which the
//! salsa canon queries deliberately do not touch (a query keyed on source text
//! must stay a pure function of that text). So this module only COLLECTS the
//! cleaned path of every constructor in a linked program, each with its span; the
//! build stage that owns the project root turns a missing file into the
//! fail-closed IPE-N0044 (Security #5: a widget cannot register against a file
//! that is not there).
//!
//! By construction a `CustomElementCtor` node appears only as the whole body of a
//! `CustomElement`-annotated binding (`resolve::detect_custom_element_constructor`
//! is the sole mint site), but this walk is exhaustive over the expression tree
//! anyway — defence in depth, so a future node placement cannot slip past the
//! existence check.

use ipe_diagnostics::Span;

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};

/// One `CustomElement.fromFile "<js-path>"` constructor reached in a linked program: its
/// CLEANED, in-project-checked relative path and the span to blame if the file
/// is absent.
#[derive(Clone, Debug)]
pub struct WidgetFile {
    /// The cleaned relative path the constructor named, ready to resolve against
    /// the project root.
    pub cleaned_path: String,
    /// The constructor's source span, for the missing-file diagnostic.
    pub span: Span,
}

/// Every `CustomElement.fromFile` constructor reached in `module`, each carrying the
/// cleaned path and its span. Empty when the program uses no widget.
#[must_use]
pub fn collect_widget_files(module: &Module) -> Vec<WidgetFile> {
    let mut out = Vec::new();
    for def in &module.defs {
        match def {
            Def::Untyped { body, .. } | Def::Typed { body, .. } => walk(body, &mut out),
        }
    }
    out
}

fn walk(e: &Expr, out: &mut Vec<WidgetFile>) {
    match &e.value {
        Expr_::CustomElementCtor(path) => out.push(WidgetFile {
            cleaned_path: path.clone(),
            span: e.span,
        }),
        Expr_::Call(f, args) => {
            walk(f, out);
            for a in args {
                walk(a, out);
            }
        }
        Expr_::ForeignCall { args, .. } => {
            for a in args {
                walk(a, out);
            }
        }
        Expr_::Case(scrut, branches) => {
            walk(scrut, out);
            for CaseBranch { body, .. } in branches {
                walk(body, out);
            }
        }
        Expr_::Lambda(_, body) => walk(body, out),
        Expr_::Let(bindings, body) => {
            for LetBinding { body: b, .. } in bindings {
                walk(b, out);
            }
            walk(body, out);
        }
        Expr_::If(branches, els) => {
            for (cond, then) in branches {
                walk(cond, out);
                walk(then, out);
            }
            walk(els, out);
        }
        Expr_::Binop { lhs, rhs, .. } => {
            walk(lhs, out);
            walk(rhs, out);
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                walk(v, out);
            }
        }
        Expr_::Update(base, fields) => {
            walk(base, out);
            for (_, v) in fields {
                walk(v, out);
            }
        }
        Expr_::Access(base, _) => walk(base, out),
        Expr_::Cons(head, tail) => {
            walk(head, out);
            walk(tail, out);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for el in elems {
                walk(el, out);
            }
        }
        // Leaves that carry no sub-expression.
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}
